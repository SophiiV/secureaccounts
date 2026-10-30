using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using SecureAccounts.Data;

namespace SecureAccounts.Services;

/// <summary>Вхід, захист від підбору пароля і журнал спроб входу.</summary>
public class AccountService(AppDbContext db, IOptions<SecurityOptions> options)
{
    private readonly SecurityOptions _opt = options.Value;

    public bool IsLockedOut(AppUser user) => user.LockoutEnd is { } end && end > DateTime.UtcNow;

    /// <summary>Невдала спроба: лічильник +1, після MaxFailedAttempts - тимчасове блокування.</summary>
    public async Task<bool> RegisterFailureAsync(AppUser user)
    {
        user.FailedLoginCount++;
        bool locked = false;
        if (user.FailedLoginCount >= _opt.MaxFailedAttempts)
        {
            user.LockoutEnd = DateTime.UtcNow.AddMinutes(_opt.LockoutMinutes);
            user.FailedLoginCount = 0;
            locked = true;
        }
        await db.SaveChangesAsync();
        return locked;
    }

    public string LockoutMessage(AppUser user) =>
        $"Забагато невдалих спроб входу. Обліковий запис тимчасово заблоковано до {Fmt.LocalTime(user.LockoutEnd!.Value)} " +
        $"({_opt.LockoutMinutes} хв).";

    public async Task LogAsync(HttpContext http, string login, AppUser? user, string method, LoginResult result)
    {
        db.LoginAttempts.Add(new LoginAttempt
        {
            Time = DateTime.UtcNow,
            Login = login.Length > 256 ? login[..256] : login,
            UserId = user?.Id,
            Ip = http.Connection.RemoteIpAddress?.ToString() ?? "",
            UserAgent = Truncate(http.Request.Headers.UserAgent.ToString(), 300),
            Method = method,
            Result = result
        });
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Завершення першого етапу входу (пароль або Google). Якщо ввімкнено 2FA - тимчасовий cookie
    /// і перехід до введення коду, інакше - повноцінний вхід. Повертає адресу для переходу.
    /// </summary>
    public async Task<string> CompleteFirstFactorAsync(HttpContext http, AppUser user, string method, string? returnUrl)
    {
        if (user.TwoFactorEnabled)
        {
            var pending = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimNames.Method, method),
                new Claim(ClaimNames.ReturnUrl, returnUrl ?? "")
            }, AuthSchemes.TwoFactor);
            await http.SignInAsync(AuthSchemes.TwoFactor, new ClaimsPrincipal(pending));
            await LogAsync(http, user.Email, user, method, LoginResult.TwoFactorRequired);
            return "/Account/LoginWith2fa";
        }
        await SignInAsync(http, user, method);
        return string.IsNullOrEmpty(returnUrl) ? "/Profile" : returnUrl;
    }

    public async Task SignInAsync(HttpContext http, AppUser user, string method)
    {
        user.FailedLoginCount = 0;
        user.LockoutEnd = null;
        user.LastLoginAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.DisplayName),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(ClaimNames.Stamp, user.SecurityStamp),
            new Claim(ClaimNames.Method, method)
        }, CookieAuthenticationDefaults.AuthenticationScheme);
        await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        await LogAsync(http, user.Email, user, method, LoginResult.Success);
    }

    public async Task<AppUser?> CurrentUserAsync(ClaimsPrincipal principal) =>
        int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out int id)
            ? await db.Users.FindAsync(id)
            : null;

    /// <summary>
    /// Перевірка cookie на кожному запиті: якщо адміністратор заблокував запис або змінився SecurityStamp
    /// (скидання пароля, блокування), сесія одразу стає недійсною.
    /// </summary>
    public static async Task ValidatePrincipalAsync(CookieValidatePrincipalContext ctx)
    {
        var db = ctx.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
        string? id = ctx.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        string? stamp = ctx.Principal?.FindFirstValue(ClaimNames.Stamp);
        AppUser? user = int.TryParse(id, out int uid) ? await db.Users.FindAsync(uid) : null;
        if (user is null || user.IsBlocked || user.SecurityStamp != stamp || user.Role != ctx.Principal?.FindFirstValue(ClaimTypes.Role))
        {
            ctx.RejectPrincipal();
            await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }

    private static string Truncate(string s, int max) => s.Length > max ? s[..max] : s;
}
