using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureAccounts.Data;
using SecureAccounts.Services;

namespace SecureAccounts.Pages.Account;

/// <summary>
/// GET лише перевіряє токен і показує кнопку, токен використовується в POST.
/// Так поштові сканери, які самі відкривають посилання з листів, не «спалять» одноразовий токен.
/// </summary>
public class ActivateModel(AppDbContext db, TokenService tokens) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? Token { get; set; }
    public bool CanActivate { get; private set; }
    public bool Success { get; private set; }
    public string Message { get; private set; } = "";
    public string? Email { get; private set; }

    public async Task OnGetAsync()
    {
        var (check, entity) = await tokens.FindAsync(Token, TokenPurpose.Activation);
        if (check != TokenCheck.Valid || entity is null)
        {
            Message = TokenService.Message(check);
            return;
        }
        CanActivate = true;
        Email = entity.User.Email;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var (check, user) = await tokens.ConsumeAsync(Token, TokenPurpose.Activation);
        if (check != TokenCheck.Valid || user is null)
        {
            Message = TokenService.Message(check);
            return Page();
        }
        user.IsActivated = true;
        user.ActivatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        Success = true;
        Message = $"Обліковий запис {user.Email} активовано.";
        return Page();
    }
}
