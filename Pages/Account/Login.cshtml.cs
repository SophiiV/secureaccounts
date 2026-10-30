using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SecureAccounts.Data;
using SecureAccounts.Services;

namespace SecureAccounts.Pages.Account;

[EnableRateLimiting("auth")]
public class LoginModel(AppDbContext db, PasswordHasher hasher, AccountService accounts, ExternalLoginOptions external)
    : PageModel
{
    private const string Generic = "Невірний email або пароль.";
    private const string Method = "Пароль";

    [BindProperty] public InputModel Input { get; set; } = new();
    public string? Error { get; private set; }
    public string? ReturnUrl { get; private set; }
    public bool GoogleEnabled => external.GoogleEnabled;

    public class InputModel
    {
        [Required(ErrorMessage = "Вкажіть email.")]
        public string Email { get; set; } = "";

        [Required(ErrorMessage = "Вкажіть пароль.")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = "";
    }

    public void OnGet(string? returnUrl, string? external)
    {
        ReturnUrl = SafeReturnUrl(returnUrl);
        if (external == "failed")
            Error = "Вхід через Google не вдався або був скасований.";
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl)
    {
        ReturnUrl = SafeReturnUrl(returnUrl);
        if (!ModelState.IsValid)
            return Page();

        string login = Input.Email.Trim().ToLowerInvariant();
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == login);

        if (user is null)
        {
            hasher.DummyVerify(Input.Password);          // однаковий час відповіді для існуючих і неіснуючих email
            await accounts.LogAsync(HttpContext, login, null, Method, LoginResult.UnknownUser);
            Error = Generic;
            return Page();
        }
        if (user.IsBlocked)
        {
            await accounts.LogAsync(HttpContext, login, user, Method, LoginResult.Blocked);
            Error = "Обліковий запис заблоковано адміністратором.";
            return Page();
        }
        if (accounts.IsLockedOut(user))
        {
            await accounts.LogAsync(HttpContext, login, user, Method, LoginResult.LockedOut);
            Error = accounts.LockoutMessage(user);
            return Page();
        }
        if (user.PasswordHash is null || !hasher.Verify(Input.Password, user.PasswordHash))
        {
            bool locked = await accounts.RegisterFailureAsync(user);
            await accounts.LogAsync(HttpContext, login, user, Method,
                locked ? LoginResult.WrongPasswordLocked : LoginResult.WrongPassword);
            Error = locked ? accounts.LockoutMessage(user) : Generic;
            return Page();
        }

        string target = await accounts.CompleteFirstFactorAsync(HttpContext, user, Method, ReturnUrl);
        return LocalRedirect(target);
    }

    private string? SafeReturnUrl(string? url) => !string.IsNullOrEmpty(url) && Url.IsLocalUrl(url) ? url : null;
}
