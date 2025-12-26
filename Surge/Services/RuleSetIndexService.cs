namespace Surge.Services;

using Microsoft.Extensions.Options;
using Options;

public sealed record RuleSetFile(string Name, string Url, long SizeBytes, DateTimeOffset LastModified);

public sealed record RuleSetCategory(string Name, IReadOnlyList<RuleSetFile> Files);

public sealed record RuleSetClient(string Name, IReadOnlyList<RuleSetCategory> Categories);

public sealed record RuleSetIndex(IReadOnlyList<RuleSetClient> Clients);

public sealed class RuleSetIndexService
{
    private static readonly string[] ClientOrder = ["Clash", "Surge", "MihomoRuleSet"];
    private static readonly string[] CategoryOrder = ["domainset", "ip", "non_ip"];
    private static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(30);

    private readonly IWebHostEnvironment _environment;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ILogger<RuleSetIndexService> _logger;
    private readonly RuleProcessingOptions _options;

    private RuleSetIndex? _cached;
    private DateTimeOffset _cachedAt;

    public RuleSetIndexService(
        ILogger<RuleSetIndexService> logger,
        IOptions<RuleProcessingOptions> options,
        IWebHostEnvironment environment)
    {
        _logger = logger;
        _options = options.Value;
        _environment = environment;
    }

    private string OutputRoot =>
        Path.Combine(
            _environment.WebRootPath ?? Path.Combine(_environment.ContentRootPath, "wwwroot"),
            _options.OutputSubdirectory);

    public async Task<RuleSetIndex> GetIndexAsync(bool forceRefresh = false, CancellationToken cancellationToken = default)
    {
        if (!forceRefresh && _cached != null && DateTimeOffset.UtcNow - _cachedAt < CacheDuration)
        {
            return _cached;
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!forceRefresh && _cached != null && DateTimeOffset.UtcNow - _cachedAt < CacheDuration)
            {
                return _cached;
            }

            var index = BuildIndex();
            _cached = index;
            _cachedAt = DateTimeOffset.UtcNow;
            return index;
        }
        finally
        {
            _gate.Release();
        }
    }

    private RuleSetIndex BuildIndex()
    {
        var root = OutputRoot;
        if (!Directory.Exists(root))
        {
            return new RuleSetIndex(Array.Empty<RuleSetClient>());
        }

        try
        {
            var clients = new List<RuleSetClient>();

            foreach (var clientName in ClientOrder)
            {
                var clientDir = Path.Combine(root, clientName);
                if (Directory.Exists(clientDir))
                {
                    clients.Add(BuildClient(clientName, clientDir));
                }
            }

            foreach (var clientDir in Directory.EnumerateDirectories(root))
            {
                var name = Path.GetFileName(clientDir);
                if (clients.Any(c => c.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                clients.Add(BuildClient(name, clientDir));
            }

            return new RuleSetIndex(clients);
        }
        catch (Exception ex) when (ex is DirectoryNotFoundException or IOException)
        {
            _logger.LogWarning(ex, "Ruleset output directory changed during enumeration.");
            return new RuleSetIndex(Array.Empty<RuleSetClient>());
        }
    }

    private RuleSetClient BuildClient(string clientName, string clientDir)
    {
        var categories = new List<RuleSetCategory>();

        foreach (var categoryName in CategoryOrder)
        {
            var categoryDir = Path.Combine(clientDir, categoryName);
            if (Directory.Exists(categoryDir))
            {
                categories.Add(BuildCategory(clientName, categoryName, categoryDir));
            }
        }

        foreach (var categoryDir in Directory.EnumerateDirectories(clientDir))
        {
            var name = Path.GetFileName(categoryDir);
            if (categories.Any(c => c.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            categories.Add(BuildCategory(clientName, name, categoryDir));
        }

        return new RuleSetClient(clientName, categories);
    }

    private RuleSetCategory BuildCategory(string clientName, string categoryName, string categoryDir)
    {
        var files = Directory.EnumerateFiles(categoryDir)
            .Select(path => CreateFile(clientName, categoryName, path))
            .OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new RuleSetCategory(categoryName, files);
    }

    private RuleSetFile CreateFile(string clientName, string categoryName, string path)
    {
        var fileName = Path.GetFileName(path);

        var url = "/" + string.Join('/', new[]
        {
            Uri.EscapeDataString(_options.OutputSubdirectory),
            Uri.EscapeDataString(clientName),
            Uri.EscapeDataString(categoryName),
            Uri.EscapeDataString(fileName)
        });

        try
        {
            var info = new FileInfo(path);
            var lastModified = info.Exists
                ? new DateTimeOffset(info.LastWriteTimeUtc)
                : DateTimeOffset.MinValue;

            return new RuleSetFile(fileName, url, info.Exists ? info.Length : 0, lastModified);
        }
        catch (IOException)
        {
            return new RuleSetFile(fileName, url, 0, DateTimeOffset.MinValue);
        }
    }
}
