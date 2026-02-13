namespace Task4.Services;

public interface IBackgroundEmailQueue
{
    ValueTask EnqueueAsync(EmailWorkItem workItem, CancellationToken cancellationToken = default);

    ValueTask<EmailWorkItem> DequeueAsync(CancellationToken cancellationToken);
}
