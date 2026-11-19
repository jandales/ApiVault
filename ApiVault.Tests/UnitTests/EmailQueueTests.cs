using System.Diagnostics;
using ApiVault.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace ApiVault.Tests.UnitTests;

public class EmailQueueTests
{
    private sealed class FakeTransport(TimeSpan delay, int failuresBeforeSuccess = 0, Func<string, bool>? alwaysFail = null) : IEmailTransport
    {
        private int _failuresLeft = failuresBeforeSuccess;
        public List<string> Delivered { get; } = [];
        public int Attempts;
        public TaskCompletionSource AllDone { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Expected { get; init; } = 1;

        public async Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Attempts);
            await Task.Delay(delay, ct);
            if (alwaysFail?.Invoke(subject) == true) throw new InvalidOperationException("smtp down");
            if (_failuresLeft-- > 0) throw new InvalidOperationException("transient");
            lock (Delivered)
            {
                Delivered.Add(subject);
                if (Delivered.Count >= Expected) AllDone.TrySetResult();
            }
        }
    }

    private static (QueuedEmailSender Sender, EmailDeliveryService Worker) Build(FakeTransport transport)
    {
        var queue = new EmailQueue();
        var sender = new QueuedEmailSender(queue, NullLogger<QueuedEmailSender>.Instance);
        var worker = new EmailDeliveryService(queue, transport, NullLogger<EmailDeliveryService>.Instance)
        {
            RetryDelays = [TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(10)],
        };
        return (sender, worker);
    }

    [Fact]
    public async Task Sending_returns_immediately_even_when_delivery_is_slow()
    {
        var transport = new FakeTransport(TimeSpan.FromSeconds(2));
        var (sender, worker) = Build(transport);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var sw = Stopwatch.StartNew();
            await sender.SendAsync("a@example.com", "Reset", "body");
            sw.Stop();
            Assert.True(sw.ElapsedMilliseconds < 200, $"enqueue took {sw.ElapsedMilliseconds} ms");

            await transport.AllDone.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(["Reset"], transport.Delivered);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Transient_failures_are_retried()
    {
        var transport = new FakeTransport(TimeSpan.Zero, failuresBeforeSuccess: 2);
        var (sender, worker) = Build(transport);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await sender.SendAsync("a@example.com", "Verify", "body");
            await transport.AllDone.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(3, transport.Attempts);
            Assert.Equal(["Verify"], transport.Delivered);
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task A_permanently_failing_email_does_not_block_the_next_one()
    {
        var transport = new FakeTransport(TimeSpan.Zero, alwaysFail: s => s == "Broken");
        var (sender, worker) = Build(transport);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await sender.SendAsync("a@example.com", "Broken", "body");
            await sender.SendAsync("b@example.com", "Fine", "body");
            await transport.AllDone.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(["Fine"], transport.Delivered);
            Assert.Equal(4, transport.Attempts); // 1 + 2 retries for "Broken", then 1 for "Fine"
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }
}
