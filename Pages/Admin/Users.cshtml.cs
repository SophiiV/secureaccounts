using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureAccounts.Data;
using SecureAccounts.Services;

namespace SecureAccounts.Pages.Admin;

/// <summary>Список користувачів і їхній статус. Доступ - лише роль Admin (Program.cs, AuthorizeFolder("/Admin")).</summary>
public class UsersModel(AppDbContext db, AccountService accounts) : PageModel
{
    public List<AppUser> Users { get; private set; } = new();
    public Dictionary<int, int> FailedLast24h { get; private set; } = new();
    public int MyId { get; private set; }

    public async Task OnGetAsync()
    {
        MyId = (await accounts.CurrentUserAsync(User))?.Id ?? 0;
        Users = await db.Users.OrderBy(u => u.Id).ToListAsync();
        var since = DateTime.UtcNow.AddHours(-24);
        var attempts = await db.LoginAttempts.Where(a => a.Time >= since && a.UserId != null).ToListAsync();
        FailedLast24h = attempts.Where(a => LoginResultInfo.IsFailure(a.Result))
            .GroupBy(a => a.UserId!.Value).ToDictionary(g => g.Key, g => g.Count());
    }

    public async Task<IActionResult> OnPostBlockAsync(int id)
    {
        var me = await accounts.CurrentUserAsync(User);
        var user = await db.Users.FindAsync(id);
        if (user is null || user.Id == me?.Id)
        {
            TempData["Error"] = "Не можна заблокувати власний обліковий запис.";
            return RedirectToPage();
        }
        user.IsBlocked = true;
        user.BlockedAt = DateTime.UtcNow;
        user.SecurityStamp = AppUser.NewStamp();   // активні сесії користувача завершуються одразу
        await db.SaveChangesAsync();
        TempData["Status"] = $"Обліковий запис {user.Email} заблоковано.";
        return RedirectToPage();
    }

    public async Task<IActionResult> OnPostUnblockAsync(int id)
    {
        var user = await db.Users.FindAsync(id);
        if (user is null)
            return RedirectToPage();
        user.IsBlocked = false;
        user.BlockedAt = null;
        user.LockoutEnd = null;                     // знімається і тимчасове блокування після підбору
        user.FailedLoginCount = 0;
        await db.SaveChangesAsync();
        TempData["Status"] = $"Обліковий запис {user.Email} розблоковано.";
        return RedirectToPage();
    }
}
