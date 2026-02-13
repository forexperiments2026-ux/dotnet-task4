using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;
using Task4.Configuration;
using Task4.Data;
using Task4.Data.Models;
using Task4.Models;
using Task4.Services;

namespace Task4.Controllers;

public class AccountController(
    AppDbContext dbContext,
    IPasswordHasher<User> passwordHasher,
    IBackgroundEmailQueue backgroundEmailQueue,
    IOptions<EmailConfirmationOptions> emailConfirmationOptions,
    ILogger<AccountController> logger) : Controller
{
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            var currentUser = await GetCurrentUserAsync();
            if (currentUser is not null && currentUser.Status != UserStatus.blocked)
            {
                return RedirectToAction("Index", "Users");
            }

            await HttpContext.SignOutAsync(AppAuthConstants.Scheme);
        }

        return View(new LoginViewModel
        {
            ReturnUrl = returnUrl
        });
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await dbContext.Users
            .SingleOrDefaultAsync(x => x.Email == model.Email);

        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid e-mail or password.");
            return View(model);
        }

        if (user.Status == UserStatus.blocked)
        {
            ModelState.AddModelError(string.Empty, "Your account is blocked.");
            return View(model);
        }

        var verificationResult = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password);
        var isValidPassword = verificationResult is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded;
        if (!isValidPassword && string.Equals(user.PasswordHash, model.Password, StringComparison.Ordinal))
        {
            isValidPassword = true;
            verificationResult = PasswordVerificationResult.SuccessRehashNeeded;
        }

        if (!isValidPassword)
        {
            ModelState.AddModelError(string.Empty, "Invalid e-mail or password.");
            return View(model);
        }

        if (verificationResult == PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = passwordHasher.HashPassword(user, model.Password);
        }

        user.LastLoginAt = DateTime.UtcNow;
        user.LastActivityAt = user.LastLoginAt;
        await dbContext.SaveChangesAsync();
        await SignInUserAsync(user, model.RememberMe);

        if (!string.IsNullOrWhiteSpace(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
        {
            return Redirect(model.ReturnUrl);
        }

        return RedirectToAction("Index", "Users");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(AppAuthConstants.Scheme);
        return RedirectToAction(nameof(Login));
    }

    [AllowAnonymous]
    public IActionResult Register()
    {
        return View(new RegisterViewModel());
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = new User
        {
            Name = $"{model.FirstName.Trim()} {model.LastName.Trim()}".Trim(),
            Email = model.Email.Trim(),
            Status = UserStatus.unverified,
            CreatedAt = DateTime.UtcNow,
            LastLoginAt = DateTime.UtcNow,
            LastActivityAt = DateTime.UtcNow
        };
        user.PasswordHash = passwordHasher.HashPassword(user, model.Password);

        dbContext.Users.Add(user);
        try
        {
            await dbContext.SaveChangesAsync();
        }
        catch (DbUpdateException ex) when (IsEmailUniqueViolation(ex))
        {
            ModelState.AddModelError(nameof(RegisterViewModel.Email), "A user with this e-mail already exists.");
            return View(model);
        }
        catch (DbUpdateException)
        {
            ModelState.AddModelError(string.Empty, "Failed to create user. Please try again.");
            return View(model);
        }

        var confirmationTokenValue = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var confirmationToken = new EmailConfirmationToken
        {
            UserId = user.Id,
            TokenHash = ComputeTokenHash(confirmationTokenValue),
            ExpiresAt = DateTime.UtcNow.AddHours(Math.Max(1, emailConfirmationOptions.Value.TokenLifetimeHours)),
            CreatedAt = DateTime.UtcNow
        };
        dbContext.EmailConfirmationTokens.Add(confirmationToken);

        try
        {
            await dbContext.SaveChangesAsync();
        }
        catch (DbUpdateException ex)
        {
            logger.LogError(ex, "Failed to store e-mail confirmation token for user {UserId}.", user.Id);
            TempData["StatusError"] = "Registration completed, but confirmation token creation failed.";
            await SignInUserAsync(user, false);
            return RedirectToAction("Index", "Users");
        }

        var confirmationLink = Url.Action(nameof(ConfirmEmail), "Account", new { token = confirmationTokenValue }, Request.Scheme);
        if (!string.IsNullOrWhiteSpace(confirmationLink))
        {
            await backgroundEmailQueue.EnqueueAsync(
                new EmailWorkItem(
                    user.Email,
                    "Confirm your e-mail",
                    BuildEmailConfirmationBody(user.Name, confirmationLink)));
        }
        else
        {
            logger.LogError("Failed to generate e-mail confirmation link for user {UserId}.", user.Id);
            TempData["StatusError"] = "Registration completed, but confirmation link generation failed.";
            await SignInUserAsync(user, false);
            return RedirectToAction("Index", "Users");
        }

        await SignInUserAsync(user, false);
        TempData["StatusSuccess"] = "Registration completed. Confirmation e-mail is queued and will be sent asynchronously.";
        return RedirectToAction("Index", "Users");
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            TempData["StatusError"] = "Confirmation link is invalid.";
            return RedirectToAction(nameof(Login));
        }

        var tokenHash = ComputeTokenHash(token);
        var tokenEntity = await dbContext.EmailConfirmationTokens
            .Include(x => x.User)
            .SingleOrDefaultAsync(x => x.TokenHash == tokenHash);

        if (tokenEntity is null || tokenEntity.UsedAt.HasValue || tokenEntity.ExpiresAt < DateTime.UtcNow)
        {
            TempData["StatusError"] = "Confirmation link is invalid or expired.";
            return RedirectToAction(nameof(Login));
        }

        tokenEntity.UsedAt = DateTime.UtcNow;
        if (tokenEntity.User.Status == UserStatus.unverified)
        {
            tokenEntity.User.Status = UserStatus.active;
            TempData["StatusSuccess"] = "E-mail confirmed successfully.";
        }
        else if (tokenEntity.User.Status == UserStatus.blocked)
        {
            TempData["StatusSuccess"] = "E-mail confirmed. Account remains blocked.";
        }
        else
        {
            TempData["StatusSuccess"] = "E-mail is already confirmed.";
        }

        await dbContext.SaveChangesAsync();
        return RedirectToAction(nameof(Login));
    }

    private async Task<User?> GetCurrentUserAsync()
    {
        var userIdRaw = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!long.TryParse(userIdRaw, out var userId))
        {
            return null;
        }

        return await dbContext.Users.SingleOrDefaultAsync(x => x.Id == userId);
    }

    private static bool IsEmailUniqueViolation(DbUpdateException exception)
    {
        return exception.InnerException is PostgresException postgresException
            && postgresException.SqlState == PostgresErrorCodes.UniqueViolation
            && string.Equals(postgresException.ConstraintName, "ux_users_email", StringComparison.Ordinal);
    }

    private async Task SignInUserAsync(User user, bool isPersistent)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Name),
            new(ClaimTypes.Email, user.Email),
            new("user_status", user.Status.ToString())
        };
        var identity = new ClaimsIdentity(claims, AppAuthConstants.Scheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(
            AppAuthConstants.Scheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = isPersistent,
                AllowRefresh = true
            });
    }

    private static string ComputeTokenHash(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(hash);
    }

    private static string BuildEmailConfirmationBody(string userName, string confirmationLink)
    {
        var encodedName = System.Net.WebUtility.HtmlEncode(userName);
        var encodedLink = System.Net.WebUtility.HtmlEncode(confirmationLink);

        return $"""
            <p>Hello, {encodedName}.</p>
            <p>Please confirm your e-mail by clicking the link below:</p>
            <p><a href="{encodedLink}">{encodedLink}</a></p>
            <p>If you did not register, ignore this message.</p>
            """;
    }
}
