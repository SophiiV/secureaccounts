using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using SecureAccounts.Data;
using SecureAccounts.Services;

namespace SecureAccounts.Pages.Account;

[EnableRateLimiting("auth")]
public class ResetPasswordModel(AppDbContext db, TokenService tokens, PasswordPolicy policy, PasswordHasher hasher)
    : PageModel
{
    [BindProperty(SupportsGet = true)] public string? Token { get; set; }
    [BindProperty] public InputModel Input { get; set; } = new();

    public bool TokenValid { get; private set; }
    public string? TokenError { get; private set; }
    public string? Email { get; private set; }
    public bool Done { get; private set; }
    public List<string> PasswordErrors { get; private set; } = new();

    public class InputModel
    {
        [Required(ErrorMessage = "Вкажіть новий пароль.")]
        [DataType(DataType.Password)]
        [Display(Name = "Новий пароль")]
        public string Password { get; set; } = "";

        [Required(ErrorMessage = "Повторіть пароль.")]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Паролі не збігаються.")]
        [Display(Name = "Повторіть пароль")]
        public string ConfirmPassword { get; set; } = "";
    }

    public async Task OnGetAsync() => await CheckTokenAsync();

    public async Task<IActionResult> OnPostAsync()
    {
        var entity = await CheckTokenAsync();
        if (entity is null)
            return Page();

        PasswordErrors = policy.Validate(Input.Password, entity.User.Email);
        foreach (string e in PasswordErrors)
            ModelState.AddModelError("Input.Password", e);
        if (!ModelState.IsValid)
            return Page();

        var (check, user) = await tokens.ConsumeAsync(Token, TokenPurpose.PasswordReset);   // одноразовість
        if (check != TokenCheck.Valid || user is null)
        {
            TokenValid = false;
            TokenError = TokenService.Message(check);
            return Page();
        }

        user.PasswordHash = hasher.Hash(Input.Password);
        user.SecurityStamp = AppUser.NewStamp();       // усі відкриті сесії цього користувача завершуються
        user.FailedLoginCount = 0;
        user.LockoutEnd = null;
        if (!user.IsActivated)                          // перехід за посиланням з листа підтверджує email
        {
            user.IsActivated = true;
            user.ActivatedAt = DateTime.UtcNow;
        }
        await db.SaveChangesAsync();
        Done = true;
        return Page();
    }

    private async Task<AccountToken?> CheckTokenAsync()
    {
        var (check, entity) = await tokens.FindAsync(Token, TokenPurpose.PasswordReset);
        TokenValid = check == TokenCheck.Valid;
        TokenError = TokenValid ? null : TokenService.Message(check);
        Email = TokenValid ? entity!.User.Email : null;
        return TokenValid ? entity : null;
    }
}
