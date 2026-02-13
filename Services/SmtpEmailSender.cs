using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;
using Task4.Configuration;

namespace Task4.Services;

public sealed class SmtpEmailSender(IOptions<SmtpOptions> options) : IEmailSender
{
    private readonly SmtpOptions smtpOptions = options.Value;

    public async Task SendEmailAsync(string to, string subject, string htmlBody, CancellationToken cancellationToken = default)
    {
        using var message = new MailMessage
        {
            Subject = subject,
            Body = htmlBody,
            IsBodyHtml = true
        };
        message.To.Add(to);
        message.From = new MailAddress(smtpOptions.FromEmail, smtpOptions.FromName);

        using var smtpClient = new SmtpClient(smtpOptions.Host, smtpOptions.Port)
        {
            EnableSsl = smtpOptions.UseSsl
        };
        if (!string.IsNullOrWhiteSpace(smtpOptions.Username))
        {
            smtpClient.Credentials = new NetworkCredential(smtpOptions.Username, smtpOptions.Password);
        }

        await smtpClient.SendMailAsync(message, cancellationToken);
    }
}
