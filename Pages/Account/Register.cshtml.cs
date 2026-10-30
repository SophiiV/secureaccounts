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
public class RegisterModel(AppDbContext db, PasswordPolicy policy, PasswordHasher hasher, CaptchaService captcha,
    TokenService tokens, EmailSender email, IOptions<SecurityOptions> security, ILogger<RegisterModel> log) : PageModel
{
    [BindProperty] public InputModel Input { get; set; } = new();
    public List<string> PasswordErrors { get; private set; } = new();

    public class InputModel
    {
        [Required(ErrorMessage = "Вкажіть ім'я.")]
        [StringLength(100, ErrorMessage = "Ім'я не довше 100 символів.")]
        [Display(Name = "Ім'я")]
        public string DisplayName { get; set; } = "";

        [Required(ErrorMessage = "Вкажіть email.")]
        [EmailAddress(ErrorMessage = "Некоректна адреса email.")]
        [StringLength(256)]
        public string Email { get; set; } = "";

        [Required(ErrorMessage = "Вкажіть пароль.")]
        [DataType(DataType.Password)]
        [Display(Name = "Пароль")]
        public string Password { get; set; } = "";

        [Required(ErrorMessage = "Повторіть пароль.")]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Паролі не збігаються.")]
        [Display(Name = "Повторіть пароль")]
        public string ConfirmPassword { get; set; } = "";

        [Required(ErrorMessage = "Введіть символи з картинки.")]
        [Display(Name = "Код з картинки")]
        public string Captcha { get; set; } = "";
    }

    public IActionResult OnGet() => User.Identity?.IsAuthenticated == true ? RedirectToPage("/Profile/Index") : Page();

    public async Task<IActionResult> OnPostAsync()
    {
        // CAPTCHA перевіряється першою і згорає після перевірки, навіть якщо інші поля з помилками
        if (!captcha.Validate(HttpContext.Session, Input.Captcha))
            ModelState.AddModelError("Input.Captcha", "Код з картинки введено неправильно або його термін минув. Спробуйте новий.");

        string normalized = (Input.Email ?? "").Trim().ToLowerInvariant();
        PasswordErrors = policy.Validate(Input.Password, normalized);
        foreach (string error in PasswordErrors)
            ModelState.AddModelError("Input.Password", error);

        if (ModelState.IsValid && await db.Users.AnyAsync(u => u.Email == normalized))
            ModelState.AddModelError("Input.Email", "Обліковий запис з таким email уже існує.");

        if (!ModelState.IsValid)
        {
            Input.Captcha = "";
            return Page();
        }

        var user = new AppUser
        {
            Email = normalized,
            DisplayName = Input.DisplayName.Trim(),
            PasswordHash = hasher.Hash(Input.Password),
            Role = Roles.User,
            IsActivated = false
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();

        int hours = security.Value.ActivationTokenHours;
        string token = await tokens.CreateAsync(user, TokenPurpose.Activation, TimeSpan.FromHours(hours));
        try
        {
            await email.SendActivationAsync(user.Email, user.DisplayName, token, hours);
        }
        catch (Exception ex)
        {
            log.LogError(ex, "Не вдалося надіслати лист активації");
            TempData["Error"] = "Обліковий запис створено, але лист не надіслано. Увійдіть і натисніть «Надіслати лист повторно» у профілі.";
        }
        return RedirectToPage("/Account/RegisterConfirmation", new { email = user.Email });
    }
}
