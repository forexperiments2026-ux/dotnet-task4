using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Task4.Data;
using Task4.Data.Models;
using Task4.Models;

namespace Task4.Middleware;

public sealed class UserAccessValidationMiddleware(RequestDelegate next)
{
    private static readonly PathString LoginPath = new("/Account/Login");
    private static readonly PathString RegisterPath = new("/Account/Register");

    public async Task InvokeAsync(HttpContext context, AppDbContext dbContext)
    {
        if (ShouldSkipValidation(context))
        {
            await next(context);
            return;
        }

        var userIdRaw = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!long.TryParse(userIdRaw, out var userId))
        {
            await InvalidateSessionAsync(context);
            return;
        }

        var userState = await dbContext.Users
            .AsNoTracking()
            .Where(x => x.Id == userId)
            .Select(x => new { x.Status })
            .SingleOrDefaultAsync();

        if (userState is null || userState.Status == UserStatus.blocked)
        {
            await InvalidateSessionAsync(context);
            return;
        }

        await next(context);
    }

    private static bool ShouldSkipValidation(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return true;
        }

        var path = context.Request.Path;
        return path.StartsWithSegments(LoginPath, StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments(RegisterPath, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task InvalidateSessionAsync(HttpContext context)
    {
        await context.SignOutAsync(AppAuthConstants.Scheme);
        context.Response.Redirect("/Account/Login");
    }
}
