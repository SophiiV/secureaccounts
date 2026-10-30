namespace SecureAccounts.Services;

/// <summary>Політика паролів: довжина, великі й малі літери, цифра, спецсимвол, заборона поширених паролів.</summary>
public class PasswordPolicy
{
    public const int MinLength = 8;
    public const int MaxLength = 128;

    // Поширені паролі, у тому числі ті, що формально проходять політику (P@ssw0rd, Qwerty123! ...)
    private static readonly HashSet<string> Common = new(StringComparer.OrdinalIgnoreCase)
    {
        "123456", "12345678", "123456789", "1234567890", "password", "password1", "qwerty", "qwerty123",
        "111111", "000000", "abc123", "iloveyou", "admin", "admin123", "welcome", "letmein", "monkey",
        "dragon", "football", "baseball", "sunshine", "princess", "master", "superman", "trustno1",
        "p@ssw0rd", "p@ssword", "passw0rd", "password!", "password1!", "password123", "password123!",
        "p@ssw0rd1", "p@ssw0rd!", "p@$$w0rd", "qwerty123!", "qwerty1!", "qwerty12!", "qwertyuiop",
        "1q2w3e4r", "1q2w3e4r!", "1qaz2wsx", "1qaz@wsx", "zaq12wsx", "zaq1@wsx", "q1w2e3r4",
        "q1w2e3r4!", "admin123!", "admin@123", "administrator1!", "welcome1", "welcome1!", "welcome123!",
        "letmein1!", "changeme", "changeme1!", "secret123!", "test123!", "test1234!", "summer2026!",
        "winter2026!", "spring2026!", "autumn2026!", "abcd1234!", "abc123!", "aa123456!", "123qwe!",
        "qwe123!", "asdf1234!", "asdfgh123!", "iloveyou1!", "football1!", "monkey123!", "dragon123!",
        "ukraine2026!", "ukraine123!", "kyiv2026!", "slavaukraini1!", "parol123!", "parol1!"
    };

    public List<string> Validate(string? password, string? email = null)
    {
        var errors = new List<string>();
        password ??= "";
        if (password.Length < MinLength)
            errors.Add($"Пароль має містити щонайменше {MinLength} символів.");
        if (password.Length > MaxLength)
            errors.Add($"Пароль не може бути довшим за {MaxLength} символів.");
        if (!password.Any(char.IsUpper))
            errors.Add("Пароль має містити велику літеру.");
        if (!password.Any(char.IsLower))
            errors.Add("Пароль має містити малу літеру.");
        if (!password.Any(char.IsDigit))
            errors.Add("Пароль має містити цифру.");
        if (!password.Any(c => !char.IsLetterOrDigit(c)))
            errors.Add("Пароль має містити символ, який не є літерою чи цифрою (наприклад ! @ # $ %).");
        if (Common.Contains(password))
            errors.Add("Це один із найпоширеніших паролів, його легко підібрати.");
        string local = (email ?? "").Split('@')[0];
        if (local.Length >= 3 && password.Contains(local, StringComparison.OrdinalIgnoreCase))
            errors.Add("Пароль не повинен містити частину вашої адреси email.");
        return errors;
    }
}
