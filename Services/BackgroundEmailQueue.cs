using System.Threading.Channels;

namespace Task4.Services;

public sealed class BackgroundEmailQueue : IBackgroundEmailQueue
{
    private readonly Channel<EmailWorkItem> channel = Channel.CreateUnbounded<EmailWorkItem>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    public ValueTask EnqueueAsync(EmailWorkItem workItem, CancellationToken cancellationToken = default)
    {
        return channel.Writer.WriteAsync(workItem, cancellationToken);
    }

    public ValueTask<EmailWorkItem> DequeueAsync(CancellationToken cancellationToken)
    {
        return channel.Reader.ReadAsync(cancellationToken);
    }
}
