using Microsoft.Extensions.Options;
using Surge.Options;

namespace Surge.Services;

public sealed class RuleProcessingHostedService : BackgroundService
{
    private readonly RuleRepositorySyncService _repoSync;
    private readonly RuleProcessingService _processor;
    private readonly ILogger<RuleProcessingHostedService> _logger;
    private readonly RuleProcessingOptions _options;
    private PeriodicTimer? _timer;

    public RuleProcessingHostedService(
        RuleRepositorySyncService repoSync,
        RuleProcessingService processor,
        ILogger<RuleProcessingHostedService> logger,
        IOptions<RuleProcessingOptions> options)
    {
        _repoSync = repoSync;
        _processor = processor;
        _logger = logger;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_options.RunOnStartup)
        {
            await RunOnceAsync(stoppingToken);
        }

        _timer = new PeriodicTimer(TimeSpan.FromDays(_options.IntervalDays));
        try
        {
            while (await _timer.WaitForNextTickAsync(stoppingToken))
            {
                await RunOnceAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // expected on shutdown
        }
    }

    private async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        try
        {
            _logger.LogInformation("Rule processing started at {Time}", DateTimeOffset.UtcNow);
            _logger.LogInformation("Repository sync started at {Time}", DateTimeOffset.UtcNow);
            _repoSync.SyncRepositories(cancellationToken);
            _logger.LogInformation("Repository sync completed at {Time}", DateTimeOffset.UtcNow);
            await _processor.ProcessAsync(cancellationToken);
            _logger.LogInformation("Rule processing completed at {Time}", DateTimeOffset.UtcNow);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Rule processing failed");
        }
    }

    public override void Dispose()
    {
        _timer?.Dispose();
        base.Dispose();
    }
}
