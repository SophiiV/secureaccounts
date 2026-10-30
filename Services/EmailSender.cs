using System.Net;
using System.Net.Mail;
using System.Text;
using Microsoft.Extensions.Options;

namespace SecureAccounts.Services;

/// <summary>Надсилання листів через SMTP (у розробці - локальний сервер Mailpit).</summary>
public class EmailSender(IOptions<SmtpOptions> smtp, IOptions<AppOptions> app, ILogger<EmailSender> log)
{
    public string BaseUrl => app.Value.BaseUrl.TrimEnd('/');

    public Task SendActivationAsync(string to, string name, string token, int hours) =>
        SendAsync(to, "Активація облікового запису SecureAccounts", Layout(name,
            "Ви зареєструвалися в системі SecureAccounts. Щоб активувати обліковий запис, перейдіть за посиланням:",
            $"{BaseUrl}/Account/Activate?token={token}", "Активувати обліковий запис",
            $"Посилання одноразове і діє {hours} год. Якщо ви не реєструвалися, просто проігноруйте цей лист."));

    public Task SendPasswordResetAsync(string to, string name, string token, int minutes) =>
        SendAsync(to, "Відновлення пароля SecureAccounts", Layout(name,
            "Ми отримали запит на відновлення пароля. Щоб встановити новий пароль, перейдіть за посиланням:",
            $"{BaseUrl}/Account/ResetPassword?token={token}", "Встановити новий пароль",
            $"Посилання одноразове і діє {minutes} хв. Якщо ви не надсилали запит, проігноруйте лист: пароль не зміниться."));

    private async Task SendAsync(string to, string subject, string html)
    {
        var o = smtp.Value;
        using var message = new MailMessage
        {
            From = new MailAddress(o.From, o.FromName, Encoding.UTF8),
            Subject = subject,
            SubjectEncoding = Encoding.UTF8,
            Body = html,
            BodyEncoding = Encoding.UTF8,
            IsBodyHtml = true
        };
        message.To.Add(to);
        using var client = new SmtpClient(o.Host, o.Port) { EnableSsl = false, DeliveryMethod = SmtpDeliveryMethod.Network };
        await client.SendMailAsync(message);
        log.LogInformation("Лист «{Subject}» надіслано на {To}", subject, to);
    }

    private static string Layout(string name, string intro, string link, string button, string note) => $"""
        <div style="font-family:Segoe UI,Arial,sans-serif;font-size:15px;color:#222;max-width:560px">
          <p>Вітаємо, {WebUtility.HtmlEncode(name)}!</p>
          <p>{intro}</p>
          <p><a href="{link}" style="display:inline-block;background:#0d6efd;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none">{button}</a></p>
          <p style="font-size:13px;color:#555">Або скопіюйте адресу в браузер:<br><a href="{link}">{link}</a></p>
          <p style="font-size:13px;color:#555">{note}</p>
        </div>
        """;
}
