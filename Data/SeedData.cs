using Microsoft.EntityFrameworkCore;
using SecureAccounts.Services;

namespace SecureAccounts.Data;

public static class SeedData
{
    /// <summary>Створює обліковий запис адміністратора з конфігурації (розділ Seed), якщо адміністратора ще немає.</summary>
    public static async Task EnsureAdminAsync(IServiceProvider services, IConfiguration config, ILogger log)
    {
        var db = services.GetRequiredService<AppDbContext>();
        await db.Database.EnsureCreatedAsync();
        if (await db.Users.AnyAsync(u => u.Role == Roles.Admin))
            return;

        string? email = config["Seed:AdminEmail"]?.Trim().ToLowerInvariant();
        string? password = config["Seed:AdminPassword"];
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
        {
            log.LogWarning("Адміністратора не створено: у конфігурації немає Seed:AdminEmail / Seed:AdminPassword");
            return;
        }
        var errors = services.GetRequiredService<PasswordPolicy>().Validate(password, email);
        if (errors.Count > 0)
            throw new InvalidOperationException("Пароль адміністратора не відповідає політиці: " + string.Join(" ", errors));

        db.Users.Add(new AppUser
        {
            Email = email,
            DisplayName = config["Seed:AdminName"] ?? "Адміністратор",
            PasswordHash = services.GetRequiredService<PasswordHasher>().Hash(password),
            Role = Roles.Admin,
            IsActivated = true,
            ActivatedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
        log.LogInformation("Створено адміністратора {Email}", email);
    }
}
