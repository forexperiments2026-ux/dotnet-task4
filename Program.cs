using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Task4.Configuration;
using Task4.Data;
using Task4.Data.Models;
using Task4.Middleware;
using Task4.Models;
using Task4.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(connectionString, npgsqlOptions =>
        npgsqlOptions.MapEnum<UserStatus>("user_status", "app")));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

var dataProtectionBuilder = builder.Services
    .AddDataProtection()
    .SetApplicationName("Task4");

var dataProtectionKeysPath = builder.Configuration["DATA_PROTECTION_KEYS_PATH"];
if (!string.IsNullOrWhiteSpace(dataProtectionKeysPath))
{
    Directory.CreateDirectory(dataProtectionKeysPath);
    dataProtectionBuilder.PersistKeysToFileSystem(new DirectoryInfo(dataProtectionKeysPath));
}

builder.Services.AddAuthentication(AppAuthConstants.Scheme)
    .AddCookie(AppAuthConstants.Scheme, options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/Login";
        options.SlidingExpiration = true;
    });
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection("Smtp"));
builder.Services.Configure<EmailConfirmationOptions>(builder.Configuration.GetSection("EmailConfirmation"));
builder.Services.AddSingleton<IBackgroundEmailQueue, BackgroundEmailQueue>();
builder.Services.AddHostedService<QueuedEmailSenderService>();
builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();
builder.Services.AddControllersWithViews();

var app = builder.Build();
var isRender = string.Equals(app.Configuration["RENDER"], "true", StringComparison.OrdinalIgnoreCase);

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

if (!isRender)
{
    app.UseHttpsRedirection();
}
app.UseRouting();

app.UseAuthentication();
app.UseMiddleware<UserAccessValidationMiddleware>();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}")
    .WithStaticAssets();

app.Run();
