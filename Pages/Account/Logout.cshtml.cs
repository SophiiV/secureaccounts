using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SecureAccounts.Pages.Account;

public class LogoutModel : PageModel
{
    public IActionResult OnGet() => RedirectToPage("/Index");   // вихід лише POST-запитом з токеном CSRF

    public async Task<IActionResult> OnPostAsync()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        HttpContext.Session.Clear();
        TempData["Status"] = "Ви вийшли з системи.";
        return RedirectToPage("/Index");
    }
}
