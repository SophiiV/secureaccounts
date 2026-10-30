using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using QRCoder;

namespace SecureAccounts.Services;

/// <summary>
/// TOTP за RFC 6238 (HMAC-SHA1, крок 30 с, 6 цифр) - сумісний з Google Authenticator,
/// Microsoft Authenticator тощо. Допускається відхилення годинника на один крок,
/// а вже використаний крок повторно не приймається.
/// </summary>
public class TotpService
{
    public const int StepSeconds = 30;
    public const string Issuer = "SecureAccounts";

    public string NewSecret() => Base32.Encode(RandomNumberGenerator.GetBytes(20));   // 160 біт

    public static long CurrentStep => DateTimeOffset.UtcNow.ToUnixTimeSeconds() / StepSeconds;

    public static string ComputeCode(byte[] key, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        byte[] hash = HMACSHA1.HashData(key, counter);
        int offset = hash[^1] & 0x0F;                                  // динамічне усічення (RFC 4226)
        int binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16)
                     | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6");
    }

    public bool Verify(string secret, string? code, long lastUsedStep, out long matchedStep)
    {
        matchedStep = 0;
        code = (code ?? "").Replace(" ", "");
        if (code.Length != 6 || !code.All(char.IsAsciiDigit))
            return false;
        byte[] key = Base32.Decode(secret);
        long now = CurrentStep;
        for (long step = now - 1; step <= now + 1; step++)
        {
            if (step <= lastUsedStep)
                continue;                                              // код уже використано
            byte[] expected = Encoding.ASCII.GetBytes(ComputeCode(key, step));
            if (CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(code)))
            {
                matchedStep = step;
                return true;
            }
        }
        return false;
    }

    public string OtpAuthUri(string account, string secret) =>
        $"otpauth://totp/{Uri.EscapeDataString(Issuer + ":" + account)}?secret={secret}" +
        $"&issuer={Uri.EscapeDataString(Issuer)}&algorithm=SHA1&digits=6&period={StepSeconds}";

    public string QrDataUri(string text)
    {
        using var generator = new QRCodeGenerator();
        using QRCodeData data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.Q);
        byte[] png = new PngByteQRCode(data).GetGraphic(6);
        return "data:image/png;base64," + Convert.ToBase64String(png);
    }

    /// <summary>Секрет групами по 4 символи - зручно вводити вручну.</summary>
    public static string Pretty(string secret) =>
        string.Join(' ', Enumerable.Range(0, (secret.Length + 3) / 4)
            .Select(i => secret.Substring(i * 4, Math.Min(4, secret.Length - i * 4))));
}

/// <summary>Base32 (RFC 4648) без доповнення - формат секретів для застосунків-автентифікаторів.</summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(byte[] data)
    {
        var sb = new StringBuilder();
        int buffer = 0, bits = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }
        if (bits > 0)
            sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] Decode(string text)
    {
        var result = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (char c in text.ToUpperInvariant())
        {
            int value = Alphabet.IndexOf(c);
            if (value < 0)
                continue;
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                result.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }
        return result.ToArray();
    }
}
