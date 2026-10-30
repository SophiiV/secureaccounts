using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using SecureAccounts.Data;
using SecureAccounts.Services;

namespace SecureAccounts.Pages.Account;

[EnableRateLimiting("auth")]
public class LoginWith2faModel(AppDbContext db, AccountService accounts, TotpService totp, IDataProtectionProvider dp)
    : PageModel
{
    [BindProperty]
    [Required(ErrorMessage = "Введіть код.")]
    public string Code { get; set; } = "";

    public string? Error { get; private set; }
    public string? Email { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var (user, _, _) = await PendingAsync();
        if (user is null)
            return RedirectToPage("/Account/Login");
        Email = user.Email;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var (user, method, returnUrl) = await PendingAsync();
        if (user is null)
            return RedirectToPage("/Account/Login");
        Email = user.Email;
        string fullMethod = method + "+TOTP";

        if (user.IsBlocked)
        {
            await accounts.LogAsync(HttpContext, user.Email, user, fullMethod, LoginResult.Blocked);
            await HttpContext.SignOutAsync(AuthSchemes.TwoFactor);
            TempData["Error"] = "Обліковий запис заблоковано адміністратором.";
            return RedirectToPage("/Account/Login");
        }
        if (accounts.IsLockedOut(user))
        {
            await accounts.LogAsync(HttpContext, user.Email, user, fullMethod, LoginResult.LockedOut);
            Error = accounts.LockoutMessage(user);
            return Page();
        }

        if (!ModelState.IsValid)
            return Page();

        string secret = dp.CreateProtector(TwoFactorProtector.Purpose).Unprotect(user.TotpSecretProtected!);
        if (!totp.Verify(secret, Code, user.LastTotpStep, out long step))
        {
            bool locked = await accounts.RegisterFailureAsync(user);
            await accounts.LogAsync(HttpContext, user.Email, user, fullMethod,
                locked ? LoginResult.WrongTotpLocked : LoginResult.WrongTotp);
            Error = locked ? accounts.LockoutMessage(user) : "Невірний код. Перевірте час на телефоні і спробуйте ще раз.";
            Code = "";
            return Page();
        }

        user.LastTotpStep = step;
        await db.SaveChangesAsync();
        await HttpContext.SignOutAsync(AuthSchemes.TwoFactor);
        await accounts.SignInAsync(HttpContext, user, fullMethod);
        return LocalRedirect(string.IsNullOrEmpty(returnUrl) || !Url.IsLocalUrl(returnUrl) ? "/Profile" : returnUrl);
    }

    private async Task<(AppUser?, string, string?)> PendingAsync()
    {
        var result = await HttpContext.AuthenticateAsync(AuthSchemes.TwoFactor);
        if (!result.Succeeded)
            return (null, "", null);
        var principal = result.Principal!;
        var user = await accounts.CurrentUserAsync(principal);
        if (user is null || !user.TwoFactorEnabled || user.TotpSecretProtected is null)
            return (null, "", null);
        return (user, principal.FindFirstValue(ClaimNames.Method) ?? "Пароль", principal.FindFirstValue(ClaimNames.ReturnUrl));
    }
}

public static class TwoFactorProtector
{
    public const string Purpose = "SecureAccounts.TotpSecret.v1";
}
