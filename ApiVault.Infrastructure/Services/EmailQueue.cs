using System.Threading.Channels;
using ApiVault.Core.Interfaces;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ApiVault.Infrastructure.Services;

/// <summary>Actually delivers an email (SMTP, or the development log).</summary>
public interface IEmailTransport
{
    Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default);
}

public record OutgoingEmail(string To, string Subject, string Body);

/// <summary>In-memory, bounded queue of emails waiting for delivery.</summary>
public class EmailQueue
{
    public const int Capacity = 1000;
    private readonly Channel<OutgoingEmail> _channel = Channel.CreateBounded<OutgoingEmail>(
        new BoundedChannelOptions(Capacity) { SingleReader = true, FullMode = BoundedChannelFullMode.DropWrite });

    public bool TryEnqueue(OutgoingEmail email) => _channel.Writer.TryWrite(email);
    public ChannelReader<OutgoingEmail> Reader => _channel.Reader;
}

/// <summary>
/// The <see cref="IEmailSender"/> used by the application. It only enqueues and returns immediately, so request
/// timing does not depend on mail delivery. Otherwise "forgot password" for a real account would be measurably
/// slower than for an unknown email, revealing which accounts exist.
/// </summary>
public class QueuedEmailSender(EmailQueue queue, ILogger<QueuedEmailSender> logger) : IEmailSender
{
    public Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        if (!queue.TryEnqueue(new OutgoingEmail(toEmail, subject, body)))
            logger.LogWarning("Email queue is full; dropped email '{Subject}'.", subject);
        return Task.CompletedTask;
    }
}

/// <summary>Background worker that delivers queued emails, retrying transient failures.</summary>
public class EmailDeliveryService(EmailQueue queue, IEmailTransport transport, ILogger<EmailDeliveryService> logger) : BackgroundService
{
    /// <summary>Delays before each retry; overridable for tests.</summary>
    public TimeSpan[] RetryDelays { get; init; } = [TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30)];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var email in queue.Reader.ReadAllAsync(stoppingToken))
                await DeliverAsync(email, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
    }

    private async Task DeliverAsync(OutgoingEmail email, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await transport.SendAsync(email.To, email.Subject, email.Body, ct);
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                if (attempt >= RetryDelays.Length)
                {
                    // Never log the body: it contains one-time tokens.
                    logger.LogError("Giving up on email '{Subject}' after {Attempts} attempts: {Error}", email.Subject, attempt + 1, ex.Message);
                    return;
                }
                logger.LogWarning("Email '{Subject}' failed (attempt {Attempt}), retrying: {Error}", email.Subject, attempt + 1, ex.Message);
                await Task.Delay(RetryDelays[attempt], ct);
            }
        }
    }
}
