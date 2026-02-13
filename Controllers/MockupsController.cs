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

public class MockupsController(AppDbContext dbContext, IPasswordHasher<User> passwordHasher) : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            var currentUser = await GetCurrentUserAsync();
            if (currentUser is not null && currentUser.Status != UserStatus.blocked)
            {
                return RedirectToAction(nameof(UserManagement));
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
                IsPersistent = model.RememberMe,
                AllowRefresh = true
            });

        if (!string.IsNullOrWhiteSpace(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
        {
            return Redirect(model.ReturnUrl);
        }

        return RedirectToAction(nameof(UserManagement));
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

        TempData["RegistrationStatus"] = "Registration completed. Confirmation e-mail is queued and will be sent asynchronously.";
        TempData["RegisteredEmail"] = user.Email;
        return RedirectToAction(nameof(RegistrationSuccess));
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = AppAuthConstants.Scheme)]
    public async Task<IActionResult> UserManagement()
    {
        var redirect = await ValidateCurrentUserAccessAsync();
        if (redirect is not null)
        {
            return redirect;
        }

        var users = await dbContext.Users
            .AsNoTracking()
            .OrderByDescending(x => x.LastLoginAt)
            .ThenBy(x => x.Id)
            .Select(x => new MockUserViewModel
            {
                Id = x.Id,
                Name = x.Name,
                Email = x.Email,
                LastActivity = (x.LastLoginAt ?? x.LastActivityAt ?? x.CreatedAt).ToString("yyyy-MM-dd HH:mm"),
                Status = x.Status.ToString(),
                IsSelected = false
            })
            .ToListAsync();

        var model = new UserManagementMockViewModel
        {
            Users = users,
            TotalUsers = users.Count,
            ActiveUsers = users.Count(u => u.Status == "active"),
            BlockedUsers = users.Count(u => u.Status == "blocked"),
            UnverifiedUsers = users.Count(u => u.Status == "unverified")
        };

        return View(model);
    }

    [HttpPost]
    [Authorize(AuthenticationSchemes = AppAuthConstants.Scheme)]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UserManagement(string operation, List<long>? selectedIds)
    {
        var redirect = await ValidateCurrentUserAccessAsync();
        if (redirect is not null)
        {
            return redirect;
        }

        var ids = selectedIds ?? [];
        var normalizedOperation = operation?.Trim().ToLowerInvariant();
        var affected = 0;

        switch (normalizedOperation)
        {
            case "block":
                if (ids.Count == 0)
                {
                    TempData["StatusError"] = "Select at least one user to block.";
                    return RedirectToAction(nameof(UserManagement));
                }

                affected = await dbContext.Users
                    .Where(x => ids.Contains(x.Id))
                    .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, UserStatus.blocked));
                TempData["StatusSuccess"] = $"Blocked users: {affected}.";
                break;

            case "unblock":
                if (ids.Count == 0)
                {
                    TempData["StatusError"] = "Select at least one user to unblock.";
                    return RedirectToAction(nameof(UserManagement));
                }

                affected = await dbContext.Users
                    .Where(x => ids.Contains(x.Id))
                    .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, UserStatus.active));
                TempData["StatusSuccess"] = $"Unblocked users: {affected}.";
                break;

            case "delete":
                if (ids.Count == 0)
                {
                    TempData["StatusError"] = "Select at least one user to delete.";
                    return RedirectToAction(nameof(UserManagement));
                }

                affected = await dbContext.Users
                    .Where(x => ids.Contains(x.Id))
                    .ExecuteDeleteAsync();
                TempData["StatusSuccess"] = $"Deleted users: {affected}.";
                break;

            case "delete-unverified":
                affected = await dbContext.Users
                    .Where(x => x.Status == UserStatus.unverified)
                    .ExecuteDeleteAsync();
                TempData["StatusSuccess"] = $"Deleted unverified users: {affected}.";
                break;

            default:
                TempData["StatusError"] = "Unknown operation.";
                break;
        }

        return RedirectToAction(nameof(UserManagement));
    }

    [AllowAnonymous]
    public IActionResult RegistrationSuccess()
    {
        return View();
    }

    [AllowAnonymous]
    public IActionResult Blocked()
    {
        return View();
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

    private async Task<IActionResult?> ValidateCurrentUserAccessAsync()
    {
        var currentUser = await GetCurrentUserAsync();
        if (currentUser is null || currentUser.Status == UserStatus.blocked)
        {
            await HttpContext.SignOutAsync(AppAuthConstants.Scheme);
            TempData["StatusError"] = "Your session is no longer valid. Please sign in again.";
            return RedirectToAction(nameof(Login));
        }

        currentUser.LastActivityAt = DateTime.UtcNow;
        await dbContext.SaveChangesAsync();
        return null;
    }

    private static bool IsEmailUniqueViolation(DbUpdateException exception)
    {
        return exception.InnerException is PostgresException postgresException
            && postgresException.SqlState == PostgresErrorCodes.UniqueViolation
            && string.Equals(postgresException.ConstraintName, "ux_users_email", StringComparison.Ordinal);
    }
}
