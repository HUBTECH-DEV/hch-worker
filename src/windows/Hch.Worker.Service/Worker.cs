namespace Hch.Worker.Service;

/// <summary>The single SCM-hosted HCH Worker process.</summary>
/// <remarks>
/// An SCM cancellation is deliberately passed only as service lifetime. It is
/// not translated to the operational Stop command and therefore never reports
/// <c>operator-stop-requested</c> for an administrative shutdown.
/// </remarks>
public sealed class Worker(
    WorkerRuntimeFactory runtimeFactory,
    ILogger<Worker> logger) : BackgroundService
{
    public const string ServiceName = "HchWorker";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await using var runtime = await runtimeFactory.CreateAsync(stoppingToken).ConfigureAwait(false);
            await runtime.RunAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal SCM shutdown. Journals own reconciliation on the next boot.
        }
        catch (Exception error)
        {
            logger.LogCritical(error, "HCH Worker runtime stopped unexpectedly ({Code}).", SafeCode(error));
            throw;
        }
    }

    private static string SafeCode(Exception error) => error switch
    {
        WorkerServiceException service => service.Code,
        OrchestratorRequestException request => request.Code,
        _ => "worker-runtime-unhandled",
    };
}
