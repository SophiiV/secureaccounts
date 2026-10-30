namespace SecureAccounts.Services;

public class SecurityOptions
{
    public int MaxFailedAttempts { get; set; } = 5;          // невдалих спроб до блокування
    public int LockoutMinutes { get; set; } = 5;             // тривалість тимчасового блокування
    public int ActivationTokenHours { get; set; } = 24;
    public int ResetTokenMinutes { get; set; } = 30;
    public int Pbkdf2Iterations { get; set; } = 600_000;
}

public class SmtpOptions
{
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 1025;
    public string From { get; set; } = "no-reply@secureaccounts.local";
    public string FromName { get; set; } = "SecureAccounts";
}

public class AppOptions
{
    // Посилання в листах будуються від цієї адреси, а не від заголовка Host запиту
    public string BaseUrl { get; set; } = "http://localhost:5080";
}

public record ExternalLoginOptions(bool GoogleEnabled);

public static class AuthSchemes
{
    public const string TwoFactor = "TwoFactor";
    public const string External = "External";
    public const string Google = "Google";
}

public static class ClaimNames
{
    public const string Stamp = "sa:stamp";
    public const string Method = "sa:method";
    public const string ReturnUrl = "sa:return";
}

public static class Fmt
{
    public static string Local(DateTime? utc) => utc is null
        ? "-"
        : TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc.Value, DateTimeKind.Utc), TimeZoneInfo.Local)
            .ToString("dd.MM.yyyy HH:mm:ss");

    public static string LocalTime(DateTime utc) =>
        TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), TimeZoneInfo.Local)
            .ToString("HH:mm:ss");
}
