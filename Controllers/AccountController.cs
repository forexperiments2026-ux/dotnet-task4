using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Task4.Data;
using Task4.Data.Models;
using Task4.Models;

namespace Task4.Controllers;

public class AccountController(AppDbContext dbContext, IPasswordHasher<User> passwordHasher) : Controller
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

        await SignInUserAsync(user, false);
        TempData["StatusSuccess"] = "Registration completed. Confirmation e-mail is queued and will be sent asynchronously.";
        return RedirectToAction("Index", "Users");
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
}
