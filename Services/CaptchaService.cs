using System.Security.Cryptography;
using System.Text;
using SkiaSharp;

namespace SecureAccounts.Services;

/// <summary>
/// Графічна CAPTCHA. Код генерується криптографічно стійким генератором, зберігається в серверній сесії
/// і перевіряється один раз: після будь-якої перевірки його видалено, тому повторно надіслати той самий
/// розв'язок не вийде. Код живе 5 хвилин.
/// </summary>
public class CaptchaService
{
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";   // без 0/O, 1/I
    private const int Length = 5;
    private const string CodeKey = "captcha.code";
    private const string ExpiresKey = "captcha.expires";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    public byte[] CreateImage(ISession session)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < Length; i++)
            sb.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);
        string code = sb.ToString();
        session.SetString(CodeKey, code);
        session.SetString(ExpiresKey, DateTime.UtcNow.Add(Lifetime).Ticks.ToString());
        return Render(code);
    }

    public bool Validate(ISession session, string? answer)
    {
        string? code = session.GetString(CodeKey);
        string? expires = session.GetString(ExpiresKey);
        session.Remove(CodeKey);                       // одноразовість
        session.Remove(ExpiresKey);
        if (code is null || expires is null || string.IsNullOrWhiteSpace(answer))
            return false;
        if (!long.TryParse(expires, out long ticks) || DateTime.UtcNow.Ticks > ticks)
            return false;
        byte[] a = Encoding.ASCII.GetBytes(answer.Trim().ToUpperInvariant());
        byte[] b = Encoding.ASCII.GetBytes(code);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static byte[] Render(string code)
    {
        const int width = 200, height = 64;
        var rnd = new Random();
        using var bitmap = new SKBitmap(width, height);
        using var canvas = new SKCanvas(bitmap);
        canvas.Clear(new SKColor(244, 246, 250));

        using var noise = new SKPaint { IsAntialias = true, StrokeWidth = 1.2f };
        for (int i = 0; i < 9; i++)
        {
            noise.Color = RandomColor(rnd, 120, 200);
            canvas.DrawLine(rnd.Next(width), rnd.Next(height), rnd.Next(width), rnd.Next(height), noise);
        }
        for (int i = 0; i < 350; i++)
        {
            noise.Color = RandomColor(rnd, 100, 220);
            canvas.DrawPoint(rnd.Next(width), rnd.Next(height), noise);
        }

        using var typeface = SKTypeface.FromFamilyName("Arial", SKFontStyle.Bold);
        using var paint = new SKPaint { IsAntialias = true };
        float x = 14;
        foreach (char ch in code)
        {
            using var font = new SKFont(typeface, rnd.Next(30, 40));
            paint.Color = RandomColor(rnd, 20, 110);
            canvas.Save();
            canvas.Translate(x, rnd.Next(40, 52));
            canvas.RotateDegrees(rnd.Next(-28, 28));
            canvas.DrawText(ch.ToString(), 0, 0, SKTextAlign.Left, font, paint);
            canvas.Restore();
            x += 34 + rnd.Next(-3, 4);
        }

        // кілька кривих Безьє поверх тексту, щоб символи важче було відокремити автоматично
        using var strike = new SKPaint { IsAntialias = true, StrokeWidth = 2, Style = SKPaintStyle.Stroke };
        for (int i = 0; i < 3; i++)
        {
            strike.Color = RandomColor(rnd, 40, 140);
            float y0 = rnd.Next(height), y1 = rnd.Next(height), y2 = rnd.Next(height), y3 = rnd.Next(height);
            float px = 0, py = y0;
            for (int s = 1; s <= 40; s++)
            {
                float t = s / 40f, u = 1 - t;
                float x1 = width * t;
                float y = u * u * u * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y3;
                canvas.DrawLine(px, py, x1, y, strike);
                px = x1;
                py = y;
            }
        }

        using var image = SKImage.FromBitmap(bitmap);
        using var data = image.Encode(SKEncodedImageFormat.Png, 100);
        return data.ToArray();
    }

    private static SKColor RandomColor(Random rnd, int min, int max) =>
        new((byte)rnd.Next(min, max), (byte)rnd.Next(min, max), (byte)rnd.Next(min, max));
}
