using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureAccounts.Data;

namespace SecureAccounts.Pages.Admin;

/// <summary>Журнал спроб входу: хто, звідки (IP), коли, яким способом і з яким результатом.</summary>
public class LoginLogModel(AppDbContext db) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? Login { get; set; }
    [BindProperty(SupportsGet = true)] public bool FailedOnly { get; set; }

    public List<LoginAttempt> Attempts { get; private set; } = new();
    public List<Summary> Summaries { get; private set; } = new();

    public record Summary(string Login, int Total, int Failed, int Succeeded, DateTime Last, string LastIp, string LastResult);

    public async Task OnGetAsync()
    {
        var all = await db.LoginAttempts.OrderByDescending(a => a.Id).Take(5000).ToListAsync();

        Summaries = all.GroupBy(a => a.Login)
            .Select(g => new Summary(g.Key, g.Count(),
                g.Count(a => LoginResultInfo.IsFailure(a.Result)),
                g.Count(a => a.Result == LoginResult.Success),
                g.First().Time, g.First().Ip, LoginResultInfo.Label(g.First().Result)))
            .OrderByDescending(s => s.Last)
            .ToList();

        IEnumerable<LoginAttempt> q = all;
        if (!string.IsNullOrWhiteSpace(Login))
            q = q.Where(a => a.Login.Contains(Login.Trim(), StringComparison.OrdinalIgnoreCase));
        if (FailedOnly)
            q = q.Where(a => LoginResultInfo.IsFailure(a.Result));
        Attempts = q.Take(300).ToList();
    }

    public async Task<IActionResult> OnPostClearAsync()
    {
        await db.LoginAttempts.ExecuteDeleteAsync();
        TempData["Status"] = "Журнал входів очищено.";
        return RedirectToPage();
    }
}
