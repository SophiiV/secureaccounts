using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureAccounts.Data;
using SecureAccounts.Services;

namespace SecureAccounts.Pages.Account;

/// <summary>
/// Вхід через Google (OpenID Connect). POST запускає перенаправлення на Google,
/// Callback отримує перевірений ID-токен (sub, email, email_verified, name) і зв'язує його з обліковим записом.
/// </summary>
public class ExternalLoginModel(AppDbContext db, AccountService accounts, ExternalLoginOptions external) : PageModel
{
    private const string Method = "Google";

    public IActionResult OnGet() => RedirectToPage("/Account/Login");

    public IActionResult OnPost(string? returnUrl)
    {
        if (!external.GoogleEnabled)
            return RedirectToPage("/Account/Login");
        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Page("/Account/ExternalLogin", "Callback", new { returnUrl })
        };
        return Challenge(props, AuthSchemes.Google);
    }

    public async Task<IActionResult> OnGetCallbackAsync(string? returnUrl)
    {
        var result = await HttpContext.AuthenticateAsync(AuthSchemes.External);
        await HttpContext.SignOutAsync(AuthSchemes.External);
        if (!result.Succeeded || result.Principal is null)
            return RedirectToPage("/Account/Login", new { external = "failed" });

        var p = result.Principal;
        string? subject = p.FindFirst("sub")?.Value;
        string? email = p.FindFirst("email")?.Value?.Trim().ToLowerInvariant();
        bool emailVerified = string.Equals(p.FindFirst("email_verified")?.Value, "true", StringComparison.OrdinalIgnoreCase);
        string name = p.FindFirst("name")?.Value ?? email ?? "Користувач Google";
        if (string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(email))
            return RedirectToPage("/Account/Login", new { external = "failed" });

        var user = await db.Users.SingleOrDefaultAsync(u => u.GoogleSubject == subject);
        if (user is null)
        {
            user = await db.Users.SingleOrDefaultAsync(u => u.Email == email);
            if (user is not null)
            {
                // прив'язка до наявного запису лише якщо Google підтвердив власність адреси
                if (!emailVerified)
                {
                    TempData["Error"] = "Google не підтвердив цю адресу email, тому прив'язати її до наявного облікового запису не можна.";
                    return RedirectToPage("/Account/Login");
                }
                user.GoogleSubject = subject;
            }
            else
            {
                user = new AppUser
                {
                    Email = email,
                    DisplayName = name.Length > 100 ? name[..100] : name,
                    PasswordHash = null,
                    Role = Roles.User,
                    GoogleSubject = subject
                };
                db.Users.Add(user);
            }
            if (emailVerified && !user.IsActivated)
            {
                user.IsActivated = true;
                user.ActivatedAt = DateTime.UtcNow;
            }
            await db.SaveChangesAsync();
        }

        if (user.IsBlocked)
        {
            await accounts.LogAsync(HttpContext, email, user, Method, LoginResult.Blocked);
            TempData["Error"] = "Обліковий запис заблоковано адміністратором.";
            return RedirectToPage("/Account/Login");
        }
        if (accounts.IsLockedOut(user))
        {
            await accounts.LogAsync(HttpContext, email, user, Method, LoginResult.LockedOut);
            TempData["Error"] = accounts.LockoutMessage(user);
            return RedirectToPage("/Account/Login");
        }

        string safeReturn = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "";
        string target = await accounts.CompleteFirstFactorAsync(HttpContext, user, Method, safeReturn);
        return LocalRedirect(target);
    }
}
