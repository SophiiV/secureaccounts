using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureAccounts.Data;
using SecureAccounts.Services;

namespace SecureAccounts.Pages.Profile;

/// <summary>Власний профіль. Користувач бачить лише свої дані: id береться з cookie, а не з параметрів запиту.</summary>
public class IndexModel(AppDbContext db, AccountService accounts, TokenService tokens, EmailSender email,
    IOptions<SecurityOptions> security) : PageModel
{
    public AppUser Me { get; private set; } = null!;
    public List<LoginAttempt> RecentAttempts { get; private set; } = new();
    public string LoginMethod { get; private set; } = "";

    public async Task<IActionResult> OnGetAsync()
    {
        var user = await accounts.CurrentUserAsync(User);
        if (user is null)
            return Challenge();
        Me = user;
        LoginMethod = User.FindFirst(ClaimNames.Method)?.Value ?? "";
        RecentAttempts = await db.LoginAttempts.Where(a => a.UserId == user.Id)
            .OrderByDescending(a => a.Id).Take(8).ToListAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostResendActivationAsync()
    {
        var user = await accounts.CurrentUserAsync(User);
        if (user is null)
            return Challenge();
        if (user.IsActivated)
            return RedirectToPage();
        int hours = security.Value.ActivationTokenHours;
        string token = await tokens.CreateAsync(user, TokenPurpose.Activation, TimeSpan.FromHours(hours));
        await email.SendActivationAsync(user.Email, user.DisplayName, token, hours);
        TempData["Status"] = $"Новий лист для активації надіслано на {user.Email}. Попереднє посилання більше не діє.";
        return RedirectToPage();
    }
}
