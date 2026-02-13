using Microsoft.Extensions.Hosting;

namespace Task4.Services;

public sealed class QueuedEmailSenderService(
    IBackgroundEmailQueue emailQueue,
    IEmailSender emailSender,
    ILogger<QueuedEmailSenderService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var workItem = await emailQueue.DequeueAsync(stoppingToken);
                await emailSender.SendEmailAsync(workItem.To, workItem.Subject, workItem.HtmlBody, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to send e-mail in background worker.");
            }
        }
    }
}
