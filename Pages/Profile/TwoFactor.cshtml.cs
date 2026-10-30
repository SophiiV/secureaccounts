using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureAccounts.Data;
using SecureAccounts.Pages.Account;
using SecureAccounts.Services;

namespace SecureAccounts.Pages.Profile;

/// <summary>
/// Увімкнення/вимкнення TOTP. Новий секрет спершу зберігається в серверній сесії і потрапляє в БД
/// (у зашифрованому вигляді) лише після того, як користувач введе правильний код - так перевіряється,
/// що застосунок-автентифікатор налаштовано.
/// </summary>
public class TwoFactorModel(AppDbContext db, AccountService accounts, TotpService totp, IDataProtectionProvider dp)
    : PageModel
{
    private const string PendingKey = "totp.pending";

    [BindProperty]
    [Required(ErrorMessage = "Введіть код.")]
    public string Code { get; set; } = "";

    public AppUser Me { get; private set; } = null!;
    public string? Secret { get; private set; }
    public string? QrDataUri { get; private set; }
    public string? Error { get; private set; }

    private IDataProtector Protector => dp.CreateProtector(TwoFactorProtector.Purpose);

    public async Task<IActionResult> OnGetAsync()
    {
        if (await LoadAsync() is { } fail)
            return fail;
        if (!Me.TwoFactorEnabled && Me.IsActivated)
            PrepareSetup();
        return Page();
    }

    public async Task<IActionResult> OnPostEnableAsync()
    {
        if (await LoadAsync() is { } fail)
            return fail;
        if (Me.TwoFactorEnabled || !Me.IsActivated)
            return RedirectToPage();
        string? pending = HttpContext.Session.GetString(PendingKey);
        if (pending is null)
            return RedirectToPage();

        if (!ModelState.IsValid || !totp.Verify(pending, Code, 0, out long step))
        {
            Error = "Код не підійшов. Перевірте, що відскановано саме цей QR-код і час на телефоні правильний.";
            PrepareSetup();
            return Page();
        }
        Me.TotpSecretProtected = Protector.Protect(pending);
        Me.TwoFactorEnabled = true;
        Me.LastTotpStep = step;
        await db.SaveChangesAsync();
        HttpContext.Session.Remove(PendingKey);
        TempData["Status"] = "Двофакторну автентифікацію ввімкнено. Під час наступного входу знадобиться код із застосунку.";
        return RedirectToPage("/Profile/Index");
    }

    public async Task<IActionResult> OnPostDisableAsync()
    {
        if (await LoadAsync() is { } fail)
            return fail;
        if (!Me.TwoFactorEnabled || Me.TotpSecretProtected is null)
            return RedirectToPage();
        string secret = Protector.Unprotect(Me.TotpSecretProtected);
        if (!ModelState.IsValid || !totp.Verify(secret, Code, Me.LastTotpStep, out _))
        {
            Error = "Невірний код. Щоб вимкнути 2FA, введіть поточний код із застосунку.";
            return Page();
        }
        Me.TwoFactorEnabled = false;
        Me.TotpSecretProtected = null;
        Me.LastTotpStep = 0;
        await db.SaveChangesAsync();
        TempData["Status"] = "Двофакторну автентифікацію вимкнено.";
        return RedirectToPage("/Profile/Index");
    }

    private async Task<IActionResult?> LoadAsync()
    {
        var user = await accounts.CurrentUserAsync(User);
        if (user is null)
            return Challenge();
        Me = user;
        return null;
    }

    private void PrepareSetup()
    {
        string? pending = HttpContext.Session.GetString(PendingKey);
        if (pending is null)
        {
            pending = totp.NewSecret();
            HttpContext.Session.SetString(PendingKey, pending);
        }
        Secret = TotpService.Pretty(pending);
        QrDataUri = totp.QrDataUri(totp.OtpAuthUri(Me.Email, pending));
        Code = "";
    }
}
