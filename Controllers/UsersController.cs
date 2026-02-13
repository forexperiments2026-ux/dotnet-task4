using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Task4.Data;
using Task4.Data.Models;
using Task4.Models;

namespace Task4.Controllers;

[Authorize(AuthenticationSchemes = AppAuthConstants.Scheme)]
public class UsersController(AppDbContext dbContext) : Controller
{
    [HttpGet]
    public async Task<IActionResult> Index(string? searchQuery)
    {
        var normalizedSearchQuery = searchQuery?.Trim() ?? string.Empty;

        var usersQuery = dbContext.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(normalizedSearchQuery))
        {
            usersQuery = usersQuery.Where(x =>
                EF.Functions.ILike(x.Name, $"%{normalizedSearchQuery}%")
                || EF.Functions.ILike(x.Email, $"%{normalizedSearchQuery}%"));
        }

        var users = await usersQuery
            .OrderByDescending(x => x.LastLoginAt)
            .ThenBy(x => x.Id)
            .Select(x => new UserListItemViewModel
            {
                Id = x.Id,
                Name = x.Name,
                Email = x.Email,
                LastActivity = (x.LastLoginAt ?? x.LastActivityAt ?? x.CreatedAt).ToString("yyyy-MM-dd HH:mm"),
                Status = x.Status.ToString(),
                IsSelected = false
            })
            .ToListAsync();

        var model = new UserManagementViewModel
        {
            Users = users,
            SearchQuery = normalizedSearchQuery,
            TotalUsers = users.Count,
            ActiveUsers = users.Count(u => u.Status == "active"),
            BlockedUsers = users.Count(u => u.Status == "blocked"),
            UnverifiedUsers = users.Count(u => u.Status == "unverified")
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(string operation, List<long>? selectedIds, string? searchQuery)
    {
        var ids = selectedIds ?? [];
        var normalizedOperation = operation?.Trim().ToLowerInvariant();
        var affected = 0;

        switch (normalizedOperation)
        {
            case "block":
                if (ids.Count == 0)
                {
                    TempData["StatusError"] = "Select at least one user to block.";
                    return RedirectToAction(nameof(Index), new { searchQuery });
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
                    return RedirectToAction(nameof(Index), new { searchQuery });
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
                    return RedirectToAction(nameof(Index), new { searchQuery });
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

        return RedirectToAction(nameof(Index), new { searchQuery });
    }
}
