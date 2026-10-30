namespace SecureAccounts.Data;

public static class Roles
{
    public const string User = "User";
    public const string Admin = "Admin";
}

public class AppUser
{
    public int Id { get; set; }
    public string Email { get; set; } = "";              // зберігається в нижньому регістрі
    public string DisplayName { get; set; } = "";
    public string? PasswordHash { get; set; }             // null - обліковий запис створено через Google
    public string Role { get; set; } = Roles.User;

    public bool IsActivated { get; set; }
    public DateTime? ActivatedAt { get; set; }

    public bool IsBlocked { get; set; }                   // блокування адміністратором
    public DateTime? BlockedAt { get; set; }
    public int FailedLoginCount { get; set; }              // невдалі спроби поспіль
    public DateTime? LockoutEnd { get; set; }              // тимчасове блокування після підбору пароля

    public bool TwoFactorEnabled { get; set; }
    public string? TotpSecretProtected { get; set; }       // секрет TOTP, зашифрований Data Protection
    public long LastTotpStep { get; set; }                 // останній використаний крок TOTP (захист від повтору)

    public string? GoogleSubject { get; set; }             // ідентифікатор sub з ID-токена Google
    public string SecurityStamp { get; set; } = NewStamp(); // змінюється - старі сесії стають недійсними

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }

    public static string NewStamp() => Guid.NewGuid().ToString("N");
}

public enum TokenPurpose
{
    Activation = 1,
    PasswordReset = 2
}

public class AccountToken
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public AppUser User { get; set; } = null!;
    public TokenPurpose Purpose { get; set; }
    public string TokenHash { get; set; } = "";            // SHA-256 від токена; сам токен не зберігається
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? UsedAt { get; set; }
}

public class LoginAttempt
{
    public long Id { get; set; }
    public DateTime Time { get; set; }
    public string Login { get; set; } = "";                // email, який ввели
    public int? UserId { get; set; }
    public string Ip { get; set; } = "";
    public string UserAgent { get; set; } = "";
    public string Method { get; set; } = "";               // Пароль, Google, Пароль+TOTP ...
    public LoginResult Result { get; set; }
}

public enum LoginResult
{
    Success = 1,
    WrongPassword = 2,
    WrongPasswordLocked = 3,
    UnknownUser = 4,
    LockedOut = 5,
    Blocked = 6,
    TwoFactorRequired = 7,
    WrongTotp = 8,
    WrongTotpLocked = 9
}

public static class LoginResultInfo
{
    public static string Label(LoginResult r) => r switch
    {
        LoginResult.Success => "Успішний вхід",
        LoginResult.WrongPassword => "Невірний пароль",
        LoginResult.WrongPasswordLocked => "Невірний пароль, запис тимчасово заблоковано",
        LoginResult.UnknownUser => "Невідомий email",
        LoginResult.LockedOut => "Спроба під час тимчасового блокування",
        LoginResult.Blocked => "Заблоковано адміністратором",
        LoginResult.TwoFactorRequired => "Пароль вірний, очікується код 2FA",
        LoginResult.WrongTotp => "Невірний код 2FA",
        LoginResult.WrongTotpLocked => "Невірний код 2FA, запис тимчасово заблоковано",
        _ => r.ToString()
    };

    public static bool IsFailure(LoginResult r) =>
        r is not (LoginResult.Success or LoginResult.TwoFactorRequired);

    public static string Css(LoginResult r) => r switch
    {
        LoginResult.Success => "text-bg-success",
        LoginResult.TwoFactorRequired => "text-bg-info",
        LoginResult.WrongPasswordLocked or LoginResult.WrongTotpLocked or LoginResult.LockedOut
            or LoginResult.Blocked => "text-bg-danger",
        _ => "text-bg-warning"
    };
}
