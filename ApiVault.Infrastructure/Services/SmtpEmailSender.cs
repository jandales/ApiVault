using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Logging;

namespace ApiVault.Infrastructure.Services;

public class SmtpOptions
{
    public const string Section = "Email:Smtp";
    /// <summary>When empty, emails are only written to the log (development).</summary>
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 587;
    public bool EnableSsl { get; set; } = true;
    public string? Username { get; set; }
    /// <summary>Keep out of appsettings: use user-secrets or an environment variable.</summary>
    public string? Password { get; set; }
    public string From { get; set; } = string.Empty;
    public string FromName { get; set; } = "API Vault";
    public bool IsConfigured => !string.IsNullOrWhiteSpace(Host) && !string.IsNullOrWhiteSpace(From);
}

/// <summary>Sends transactional email (verification, password reset) through an SMTP server.</summary>
public class SmtpEmailSender(SmtpOptions options, ILogger<SmtpEmailSender> logger) : IEmailTransport
{
    public async Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        using var message = new MailMessage
        {
            From = new MailAddress(options.From, options.FromName),
            Subject = subject,
            Body = body,
            IsBodyHtml = false,
        };
        message.To.Add(toEmail);

        using var client = new SmtpClient(options.Host, options.Port)
        {
            EnableSsl = options.EnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
        };
        if (!string.IsNullOrEmpty(options.Username))
            client.Credentials = new NetworkCredential(options.Username, options.Password);

        await client.SendMailAsync(message, ct);
        logger.LogInformation("Sent email '{Subject}' via {Host}", subject, options.Host);
    }
}
