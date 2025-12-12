namespace Surge.Services;

using System.Text;
using Microsoft.Extensions.Options;
using Options;

public sealed record RuleSetFileContent(
    string Client,
    string Category,
    string Name,
    string RawUrl,
    string Content,
    long SizeBytes,
    DateTimeOffset LastModified);

public sealed class RuleSetFileService
{
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<RuleSetFileService> _logger;
    private readonly RuleProcessingOptions _options;

    public RuleSetFileService(
        ILogger<RuleSetFileService> logger,
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

    public string GetRawUrl(string clientName, string categoryName, string fileName)
    {
        var subdir = _options.OutputSubdirectory.Trim('/');

        return "/" + string.Join('/', new[]
        {
            Uri.EscapeDataString(subdir),
            Uri.EscapeDataString(clientName),
            Uri.EscapeDataString(categoryName),
            Uri.EscapeDataString(fileName)
        });
    }

    public async Task<RuleSetFileContent?> GetFileAsync(
        string clientName,
        string categoryName,
        string fileName,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientName) ||
            string.IsNullOrWhiteSpace(categoryName) ||
            string.IsNullOrWhiteSpace(fileName))
        {
            return null;
        }

        var root = Path.GetFullPath(OutputRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var candidate = Path.GetFullPath(Path.Combine(root, clientName, categoryName, fileName));

        if (!candidate.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Rejected ruleset file path traversal attempt: {Path}", candidate);
            return null;
        }

        if (!File.Exists(candidate))
        {
            return null;
        }

        try
        {
            var content = await File.ReadAllTextAsync(candidate, Encoding.UTF8, cancellationToken);
            var info = new FileInfo(candidate);
            var lastModified = info.Exists
                ? new DateTimeOffset(info.LastWriteTimeUtc)
                : DateTimeOffset.MinValue;

            return new RuleSetFileContent(
                clientName,
                categoryName,
                fileName,
                GetRawUrl(clientName, categoryName, fileName),
                content,
                info.Exists ? info.Length : 0,
                lastModified);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Failed to read ruleset file {Path}", candidate);
            return null;
        }
    }
}

