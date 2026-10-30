using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureAccounts.Data;
using SecureAccounts.Services;

namespace SecureAccounts.Pages.Account;

[EnableRateLimiting("auth")]
public class ForgotPasswordModel(AppDbContext db, TokenService tokens, EmailSender email,
    IOptions<SecurityOptions> security, ILogger<ForgotPasswordModel> log) : PageModel
{
    [BindProperty]
    [Required(ErrorMessage = "Вкажіть email.")]
    [EmailAddress(ErrorMessage = "Некоректна адреса email.")]
    public string Email { get; set; } = "";

    public bool Sent { get; private set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
            return Page();

        string normalized = Email.Trim().ToLowerInvariant();
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == normalized);
        if (user is not null && !user.IsBlocked)
        {
            int minutes = security.Value.ResetTokenMinutes;
            string token = await tokens.CreateAsync(user, TokenPurpose.PasswordReset, TimeSpan.FromMinutes(minutes));
            try
            {
                await email.SendPasswordResetAsync(user.Email, user.DisplayName, token, minutes);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Не вдалося надіслати лист відновлення пароля");
            }
        }
        // однакова відповідь для існуючих і неіснуючих адрес - перелік користувачів не розкривається
        Sent = true;
        return Page();
    }
}
