namespace Surge.Services;

using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using Options;

public sealed class RuleProcessingService {
    private static readonly HashSet<string> NonIpPrefixes = new(
    new[]
    {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
        "USER-AGENT", "URL-REGEX", "PROCESS-NAME"
    }, StringComparer.OrdinalIgnoreCase);

    private readonly IWebHostEnvironment _environment;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private readonly ILogger<RuleProcessingService> _logger;
    private readonly RuleProcessingOptions _options;

    public RuleProcessingService(
        ILogger<RuleProcessingService> logger,
        IOptions<RuleProcessingOptions> options,
        IWebHostEnvironment environment)
    {
        _logger = logger;
        _options = options.Value;
        _environment = environment;
    }

    private string RepositoryRoot => Path.GetFullPath(Path.Combine(_environment.ContentRootPath, _options.SourceDirectory));
    private string OutputRoot => Path.Combine(_environment.WebRootPath ?? Path.Combine(_environment.ContentRootPath, "wwwroot"), _options.OutputSubdirectory);

    public async Task ProcessAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var repoRoot = RepositoryRoot;
            if (!Directory.Exists(repoRoot))
            {
                throw new DirectoryNotFoundException($"Rule repository not found at {repoRoot}");
            }

            var sourceClash = Path.Combine(repoRoot, "rule", "Clash");
            var sourceSurge = Path.Combine(repoRoot, "rule", "Surge");
            var outputRoot = OutputRoot;

            if (Directory.Exists(outputRoot))
            {
                Directory.Delete(outputRoot, true);
            }
            Directory.CreateDirectory(outputRoot);

            await ProcessClientAsync(sourceClash, Path.Combine(outputRoot, "Clash"), "txt", cancellationToken);
            await ProcessClientAsync(sourceSurge, Path.Combine(outputRoot, "Surge"), "conf", cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private Task ProcessClientAsync(string sourceRoot, string outputRoot, string extension, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(sourceRoot))
        {
            throw new DirectoryNotFoundException($"Missing source directory {sourceRoot}");
        }

        Directory.CreateDirectory(outputRoot);

        var aggregate = new Dictionary<string, RuleSegmentsBuilder>(StringComparer.OrdinalIgnoreCase);

        foreach (var directory in Directory.EnumerateDirectories(sourceRoot))
        {
            var category = Path.GetFileName(directory)!;
            foreach (var file in Directory.EnumerateFiles(directory))
            {
                ProcessFile(file, category, aggregate, cancellationToken);
            }
        }

        foreach (var file in Directory.EnumerateFiles(sourceRoot))
        {
            var category = Path.GetFileNameWithoutExtension(file);
            ProcessFile(file, category, aggregate, cancellationToken);
        }

        foreach (var (category, builder) in aggregate)
        {
            WriteCategorySegments(outputRoot, category, extension, builder);
        }

        return Task.CompletedTask;
    }

    private void ProcessFile(
        string filePath,
        string category,
        IDictionary<string, RuleSegmentsBuilder> aggregate,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var fileExtension = Path.GetExtension(filePath);
        if (fileExtension.Equals(".md", StringComparison.OrdinalIgnoreCase) ||
            fileExtension.Equals(".yaml", StringComparison.OrdinalIgnoreCase) ||
            fileExtension.Equals(".yml", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var builder = aggregate.TryGetValue(category, out var existing)
            ? existing
            : aggregate[category] = new RuleSegmentsBuilder(category);

        var segments = Classify(File.ReadLines(filePath), filePath);
        builder.Append(segments);

        _logger.LogInformation(
        "Processed {File} into {Category} (ip={IpCount}, non-ip={NonIpCount}, domainset={DomainCount})",
        filePath,
        category,
        segments.Ip.Count,
        segments.NonIp.Count,
        segments.DomainSet.Count);
    }

    private static void WriteCategorySegments(
        string outputRoot,
        string category,
        string extension,
        RuleSegmentsBuilder builder)
    {
        var targetName = $"{category}.{extension}";
        if (builder.Ip.Count > 0)
        {
            WriteSegment(Path.Combine(outputRoot, "ip"), targetName, builder.Ip);
        }

        if (builder.NonIp.Count > 0)
        {
            WriteSegment(Path.Combine(outputRoot, "non_ip"), targetName, builder.NonIp);
        }
        if (builder.DomainSet.Count > 0)
        {
            WriteSegment(Path.Combine(outputRoot, "domainset"), targetName, builder.DomainSet);
        }

    }

    private static RuleSegments Classify(IEnumerable<string> lines, string origin)
    {
        var ip = new List<string>();
        var nonIp = new List<string>();
        var domainSet = new List<string>();

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith("#") || line.StartsWith("//"))
            {
                continue;
            }

            if (!line.Contains(','))
            {
                domainSet.Add(NormalizeDomain(line, origin));
                continue;
            }

            var commaIndex = line.IndexOf(',');
            var type = line[..commaIndex].Trim();
            var payload = line[(commaIndex + 1)..].Trim();

            if (type.Equals("IP-CIDR", StringComparison.OrdinalIgnoreCase) ||
                type.Equals("IP-CIDR6", StringComparison.OrdinalIgnoreCase))
            {
                var isNoResolve = payload.Contains("no-resolve", StringComparison.OrdinalIgnoreCase);
                if (isNoResolve)
                {
                    nonIp.Add(line);
                }
                else if (IsIpPayload(payload))
                {
                    ip.Add(line);
                }
                else
                {
                    throw new InvalidDataException($"Unexpected IP payload '{payload}' in {origin}");
                }

                continue;
            }

            if (type.Equals("IP-ASN", StringComparison.OrdinalIgnoreCase))
            {
                if (IsAsn(payload))
                {
                    ip.Add(line);
                    continue;
                }

                throw new InvalidDataException($"Invalid ASN payload '{payload}' in {origin}");
            }

            if (NonIpPrefixes.Contains(type))
            {
                nonIp.Add(line);
                continue;
            }

            if (IsIpLiteral(line))
            {
                ip.Add(line);
                continue;
            }

            domainSet.Add(NormalizeDomain(payload, origin));
        }

        return new RuleSegments(ip, nonIp, domainSet);
    }

    private static bool IsIpPayload(string payload)
    {
        var core = payload.Split(',', 2, StringSplitOptions.TrimEntries)[0];
        return IsCidr(core) || IPAddress.TryParse(core, out _);
    }

    private static bool IsCidr(string value)
    {
        var parts = value.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2)
        {
            return false;
        }

        if (!int.TryParse(parts[1], out var prefix))
        {
            return false;
        }

        return IPAddress.TryParse(parts[0], out var address) &&
               ((address.AddressFamily == AddressFamily.InterNetwork && prefix is >= 0 and <= 32) ||
                (address.AddressFamily == AddressFamily.InterNetworkV6 && prefix is >= 0 and <= 128));
    }

    private static bool IsAsn(string payload)
    {
        var core = payload.Split(',', 2, StringSplitOptions.TrimEntries)[0];
        if (core.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
        {
            core = core[2..];
        }

        return int.TryParse(core, out _);
    }

    private static bool IsIpLiteral(string value)
    {
        return IPAddress.TryParse(value, out _);
    }

    private static string NormalizeDomain(string input, string origin)
    {
        var domain = input.Trim();
        if (domain.StartsWith('.'))
        {
            domain = domain[1..];
        }

        if (domain.Length == 0)
        {
            throw new InvalidDataException($"Empty domain entry detected in {origin}");
        }

        return domain.ToLowerInvariant();
    }

    private static void WriteSegment(string directory, string fileName, IReadOnlyCollection<string> lines)
    {
        Directory.CreateDirectory(directory);
        var targetPath = Path.Combine(directory, fileName);
        File.WriteAllLines(targetPath, lines);
    }

    private sealed record RuleSegments(List<string> Ip, List<string> NonIp, List<string> DomainSet);

    private sealed class RuleSegmentsBuilder {
        public RuleSegmentsBuilder(string category)
        {
            Category = category;
        }

        public string Category { get; }
        public List<string> Ip { get; } = new();
        public List<string> NonIp { get; } = new();
        public List<string> DomainSet { get; } = new();

        public void Append(RuleSegments segments)
        {
            Ip.AddRange(segments.Ip);
            NonIp.AddRange(segments.NonIp);
            DomainSet.AddRange(segments.DomainSet);
        }
    }
}
