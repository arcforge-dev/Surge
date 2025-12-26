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

    private static readonly HashSet<string> NoCategorys = new(
    new[]
    {
        "ip", "non_ip", "domainset"
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

            var personalRulesRoot = Path.GetFullPath(Path.Combine(_environment.ContentRootPath, "Rules"));
            var personalClash = personalRulesRoot;
            var personalSurge = personalRulesRoot;
            var sourceBlackClash = Path.Combine(repoRoot, "ios_rule_script", "rule", "Clash");
            var sourceBlackSurge = Path.Combine(repoRoot, "ios_rule_script", "rule", "Surge");
            var sourceSkkClash = Path.Combine(repoRoot, "ruleset.skk.moe", "Clash");
            var sourceSkkSurge = Path.Combine(repoRoot, "ruleset.skk.moe", "List");
            var outputRoot = OutputRoot;

            if (Directory.Exists(outputRoot))
            {
                Directory.Delete(outputRoot, true);
            }
            Directory.CreateDirectory(outputRoot);

            if (!Directory.Exists(personalRulesRoot))
            {
                _logger.LogWarning("Built-in rules directory not found at {Path}. Skipping built-in rules.", personalRulesRoot);
            }
            else
            {
                await ProcessClientAsync(personalClash, Path.Combine(outputRoot, "Clash"), "txt", false, cancellationToken);
                await ProcessClientAsync(personalSurge, Path.Combine(outputRoot, "Surge"), "conf", false, cancellationToken);
            }
            await ProcessClientAsync(sourceSkkClash, Path.Combine(outputRoot, "Clash"), "txt", true, cancellationToken);
            await ProcessClientAsync(sourceSkkSurge, Path.Combine(outputRoot, "Surge"), "conf", true, cancellationToken);
            await ProcessClientAsync(sourceBlackClash, Path.Combine(outputRoot, "Clash"), "txt", true, cancellationToken);
            await ProcessClientAsync(sourceBlackSurge, Path.Combine(outputRoot, "Surge"), "conf", true, cancellationToken);

            await BuildMihomoRuleSetAsync(
                Path.Combine(outputRoot, "Clash"),
                Path.Combine(outputRoot, "MihomoRuleSet"),
                cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private Task BuildMihomoRuleSetAsync(
        string clashRoot,
        string mihomoRoot,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(clashRoot))
        {
            _logger.LogWarning("Cannot build MihomoRuleSet. Clash output not found at {ClashRoot}", clashRoot);
            return Task.CompletedTask;
        }

        if (Directory.Exists(mihomoRoot))
        {
            Directory.Delete(mihomoRoot, recursive: true);
        }

        Directory.CreateDirectory(mihomoRoot);
        var aggregate = new Dictionary<string, MihomoRuleSegments>(StringComparer.OrdinalIgnoreCase);

        ProcessMihomoCategory(
            Path.Combine(clashRoot, "domainset"),
            aggregate,
            MihomoDefaultCategory.DomainSet,
            cancellationToken);

        ProcessMihomoCategory(
            Path.Combine(clashRoot, "ip"),
            aggregate,
            MihomoDefaultCategory.Mixed,
            cancellationToken);

        ProcessMihomoCategory(
            Path.Combine(clashRoot, "non_ip"),
            aggregate,
            MihomoDefaultCategory.Mixed,
            cancellationToken);

        WriteMihomoSegments(mihomoRoot, aggregate);

        _logger.LogInformation(
            "Built MihomoRuleSet at {MihomoRoot}. Files={FileCount}, domain lines={DomainCount}, ip lines={IpCount}, non-ip lines={NonIpCount}",
            mihomoRoot,
            aggregate.Count,
            aggregate.Values.Sum(x => x.Domain.Count),
            aggregate.Values.Sum(x => x.Ip.Count),
            aggregate.Values.Sum(x => x.NonIp.Count));

        return Task.CompletedTask;
    }

    private Task ProcessClientAsync(string sourceRoot, string outputRoot, string extension, bool thirdParty, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(sourceRoot))
        {
            throw new DirectoryNotFoundException($"Missing source directory {sourceRoot}");
        }

        Directory.CreateDirectory(outputRoot);

        var aggregate = new Dictionary<string, RuleSegmentsBuilder>(StringComparer.OrdinalIgnoreCase);

        foreach (var directory in Directory.EnumerateDirectories(sourceRoot))
        {
            foreach (var file in Directory.EnumerateFiles(directory))
            {
                var category = Path.GetFileName(directory)!;
                if (!thirdParty)
                {
                    category = "arcforge_" + Path.GetFileNameWithoutExtension(file);
                }
                else
                {
                    if (NoCategorys.Contains(category))
                    {
                        category = "skk_" + Path.GetFileNameWithoutExtension(file);
                    }
                    else
                    {
                        category = "black_" + category;
                    }
                }
                ProcessFile(file, category.ToLower(), aggregate, cancellationToken);
            }
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
            fileExtension.Equals(".yml", StringComparison.OrdinalIgnoreCase) ||
            fileExtension.Equals(".sgmodule", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }
        if (filePath.Contains("Resolve", StringComparison.OrdinalIgnoreCase))
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

    private void ProcessMihomoCategory(
        string sourceDir,
        IDictionary<string, MihomoRuleSegments> aggregate,
        MihomoDefaultCategory defaultCategory,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(sourceDir))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(sourceDir).OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            var fileName = Path.GetFileName(file);
            var segments = aggregate.TryGetValue(fileName, out var existing)
                ? existing
                : aggregate[fileName] = new MihomoRuleSegments();

            foreach (var raw in File.ReadLines(file))
            {
                cancellationToken.ThrowIfCancellationRequested();

                var line = TrimRuleLine(raw);
                if (line is null)
                {
                    continue;
                }

                if (TryClassifyMihomoLine(line, segments))
                {
                    continue;
                }

                if (defaultCategory == MihomoDefaultCategory.DomainSet)
                {
                    segments.Domain.Add(line);
                    continue;
                }

                if (TryAddIpLiteral(line, segments.Ip))
                {
                    continue;
                }

                segments.NonIp.Add(line);
            }
        }
    }

    private bool TryClassifyMihomoLine(string line, MihomoRuleSegments segments)
    {
        var commaIndex = line.IndexOf(',');
        if (commaIndex <= 0)
        {
            return false;
        }

        var keyword = line[..commaIndex].Trim();
        var payload = line[(commaIndex + 1)..];

        if (keyword.Equals("DOMAIN", StringComparison.OrdinalIgnoreCase))
        {
            var domain = NormalizeDomainForMihomo(payload, allowLeadingPlus: false);
            if (domain.Length > 0)
            {
                segments.Domain.Add(domain);
            }

            return true;
        }

        if (keyword.Equals("DOMAIN-SUFFIX", StringComparison.OrdinalIgnoreCase))
        {
            var domain = NormalizeDomainForMihomo(payload, allowLeadingPlus: false);
            if (domain.Length > 0)
            {
                segments.Domain.Add("+." + domain);
            }

            return true;
        }

        if (keyword.Equals("IP-CIDR", StringComparison.OrdinalIgnoreCase) ||
            keyword.Equals("IP-CIDR6", StringComparison.OrdinalIgnoreCase))
        {
            var ip = ExtractPrimaryValue(payload);
            if (!string.IsNullOrEmpty(ip))
            {
                segments.Ip.Add(ip);
            }

            return true;
        }

        return false;
    }

    private static string? TrimRuleLine(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var line = raw.Trim();
        if (line.StartsWith("#") || line.StartsWith("//"))
        {
            return null;
        }

        return line;
    }

    private static string NormalizeDomainForMihomo(string input, bool allowLeadingPlus)
    {
        var core = ExtractPrimaryValue(input);
        var hasPlusPrefix = core.StartsWith("+.");
        core = hasPlusPrefix ? core[2..] : core;

        core = core.TrimStart('.').Trim();
        if (core.Length == 0)
        {
            return string.Empty;
        }

        var normalized = core.ToLowerInvariant();
        if (allowLeadingPlus && hasPlusPrefix)
        {
            return "+." + normalized;
        }

        return normalized;
    }

    private static string ExtractPrimaryValue(string input)
    {
        var value = input.Trim();
        var commaIndex = value.IndexOf(',');
        if (commaIndex >= 0)
        {
            value = value[..commaIndex];
        }

        return value.Trim();
    }

    private static bool TryAddIpLiteral(string line, ICollection<string> target)
    {
        var core = ExtractPrimaryValue(line);
        if (IsCidr(core) || IPAddress.TryParse(core, out _))
        {
            target.Add(core);
            return true;
        }

        return false;
    }

    private static void WriteMihomoSegments(string mihomoRoot, IDictionary<string, MihomoRuleSegments> aggregate)
    {
        if (aggregate.Count == 0)
        {
            return;
        }

        foreach (var (fileName, segments) in aggregate.OrderBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase))
        {
            WriteMihomoCategory(Path.Combine(mihomoRoot, "domainset"), fileName, segments.Domain);
            WriteMihomoCategory(Path.Combine(mihomoRoot, "ip"), fileName, segments.Ip);
            WriteMihomoCategory(Path.Combine(mihomoRoot, "non_ip"), fileName, segments.NonIp);
        }
    }

    private static void WriteMihomoCategory(string directory, string fileName, List<string> lines)
    {
        if (lines.Count == 0)
        {
            return;
        }

        Directory.CreateDirectory(directory);
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss'Z'");
        var header = new List<string>
        {
            "#########################################",
            "# ArcForge Surge Output",
            $"# Last Updated: {timestamp}",
            $"# Rule Count: {lines.Count}",
            "#",
            "# Generated by: ArcForge Surge (MIT License)",
            "# Generator Source: https://github.com/arcforge-dev/Surge",
            "#",
            "#",
            "# Disclaimer:",
            "#   This file is provided WITHOUT ANY WARRANTY.",
            "#   Use at your own risk.",
            "#########################################"
        };

        header.AddRange(lines);
        File.WriteAllLines(Path.Combine(directory, fileName), header);
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
            if (line.Contains("ruleset.skk.moe"))
            {
                continue;
            }
            if (!line.Contains(','))
            {
                if (IsCidr(line) || IPAddress.TryParse(line, out _))
                {
                    ip.Add(line);
                    continue;
                }
                domainSet.Add(NormalizeDomain(line, origin));
                continue;
            }

            var commaIndex = line.IndexOf(',');
            var type = line[..commaIndex].Trim();
            var payload = line[(commaIndex + 1)..].Trim();

            if (type.Equals("IP-CIDR", StringComparison.OrdinalIgnoreCase) ||
                type.Equals("IP-CIDR6", StringComparison.OrdinalIgnoreCase) ||
                type.Equals("IP-ASN", StringComparison.OrdinalIgnoreCase))
            {
                if (IsIpPayload(payload) || IsAsn(payload))
                {
                    ip.Add(line);
                }
                else
                {
                    throw new InvalidDataException($"Unexpected IP or non-IP payload '{payload}' in {origin}");
                }

                continue;
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

            nonIp.Add(line);


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

        return input.ToLowerInvariant();
    }

    private static void WriteSegment(string directory, string fileName, IReadOnlyCollection<string> lines)
    {
        Directory.CreateDirectory(directory);
        var targetPath = Path.Combine(directory, fileName);
        var headerLines = default(List<string>);
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss'Z'");
        if (fileName.StartsWith("skk_", StringComparison.OrdinalIgnoreCase))
        {
            headerLines = new List<string>(16)
            {
                "#########################################",
                "# ArcForge Surge Output",
                $"# Last Updated: {timestamp}",
                $"# Rule Count: {lines.Count}",
                "#",
                "# License: AGPL-3.0",
                "# Derived from: https://github.com/SukkaW/Surge",
                "#",
                "# Generated by: ArcForge Surge (MIT License)",
                "# Generator Source: https://github.com/arcforge-dev/Surge",
                "#",
                "# Data Sources:",
                "#   - Sukka Ruleset (AGPL-3.0)",
                "#",
                "# Disclaimer:",
                "#   This file is provided WITHOUT ANY WARRANTY.",
                "#   Use at your own risk.",
                "#########################################"
            };
        }
        else if (fileName.StartsWith("black_", StringComparison.OrdinalIgnoreCase) || fileName.StartsWith("arcforge_", StringComparison.OrdinalIgnoreCase))
        {
            headerLines = new List<string>(16)
            {
                "#########################################",
                "# ArcForge Surge Output",
                $"# Last Updated: {timestamp}",
                $"# Rule Count: {lines.Count}",
                "#",
                "# License: GPL-2.0",
                "# Derived from: https://github.com/blackmatrix7/ios_rule_script",
                "#",
                "# Generated by: ArcForge Surge (MIT License)",
                "# Generator Source: https://github.com/arcforge-dev/Surge",
                "#",
                "# Data Sources:",
                "#   - blackmatrix7 Ruleset (GPL-2.0)",
                "#",
                "# Disclaimer:",
                "#   This file is provided WITHOUT ANY WARRANTY.",
                "#   Use at your own risk.",
                "#########################################"
            };
        }

        if (headerLines is not null)
        {
            headerLines.AddRange(lines);
            File.WriteAllLines(targetPath, headerLines);
            return;
        }

        File.WriteAllLines(targetPath, lines);
    }

    private sealed class MihomoRuleSegments
    {
        public List<string> Domain { get; } = new();
        public List<string> Ip { get; } = new();
        public List<string> NonIp { get; } = new();
    }

    private enum MihomoDefaultCategory
    {
        DomainSet,
        Mixed
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
