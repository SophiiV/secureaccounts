using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using SecureAccounts.Data;

namespace SecureAccounts.Services;

public enum TokenCheck { Valid, NotFound, Used, Expired }

/// <summary>
/// Одноразові токени для активації облікового запису та відновлення пароля.
/// Токен - 32 випадкові байти (256 біт) у Base64url. У БД зберігається лише SHA-256 від токена,
/// тому витік бази не дає готових посилань. Токен має термін дії і після використання позначається.
/// </summary>
public class TokenService(AppDbContext db)
{
    public async Task<string> CreateAsync(AppUser user, TokenPurpose purpose, TimeSpan lifetime)
    {
        // попередні невикористані токени того самого призначення стають недійсними
        var old = await db.Tokens
            .Where(t => t.UserId == user.Id && t.Purpose == purpose && t.UsedAt == null)
            .ToListAsync();
        foreach (var t in old)
            t.UsedAt = DateTime.UtcNow;

        string token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        db.Tokens.Add(new AccountToken
        {
            UserId = user.Id,
            Purpose = purpose,
            TokenHash = HashToken(token),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.Add(lifetime)
        });
        await db.SaveChangesAsync();
        return token;
    }

    /// <summary>Перевіряє токен без використання (для показу форми).</summary>
    public async Task<(TokenCheck, AccountToken?)> FindAsync(string? token, TokenPurpose purpose)
    {
        if (string.IsNullOrWhiteSpace(token))
            return (TokenCheck.NotFound, null);
        string hash = HashToken(token);
        var entity = await db.Tokens.Include(t => t.User)
            .SingleOrDefaultAsync(t => t.TokenHash == hash && t.Purpose == purpose);
        if (entity is null)
            return (TokenCheck.NotFound, null);
        if (entity.UsedAt is not null)
            return (TokenCheck.Used, entity);
        if (entity.ExpiresAt <= DateTime.UtcNow)
            return (TokenCheck.Expired, entity);
        return (TokenCheck.Valid, entity);
    }

    /// <summary>Перевіряє і одразу позначає токен використаним.</summary>
    public async Task<(TokenCheck, AppUser?)> ConsumeAsync(string? token, TokenPurpose purpose)
    {
        var (check, entity) = await FindAsync(token, purpose);
        if (check != TokenCheck.Valid || entity is null)
            return (check, null);
        entity.UsedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        return (TokenCheck.Valid, entity.User);
    }

    public static string Message(TokenCheck check) => check switch
    {
        TokenCheck.NotFound => "Посилання недійсне.",
        TokenCheck.Used => "Це посилання вже використано. Кожне посилання діє лише один раз.",
        TokenCheck.Expired => "Термін дії посилання минув. Запросіть новий лист.",
        _ => ""
    };

    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
