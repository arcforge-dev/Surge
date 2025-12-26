namespace Surge.Services;

using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Options;
using Options;

public sealed class RuleRepositorySyncService
{
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<RuleRepositorySyncService> _logger;
    private readonly RuleProcessingOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private static readonly Uri SkkRepo = new("https://github.com/SukkaLab/ruleset.skk.moe");
    private static readonly Uri BlackmatrixRepo = new("https://github.com/blackmatrix7/ios_rule_script");

    public RuleRepositorySyncService(
        ILogger<RuleRepositorySyncService> logger,
        IOptions<RuleProcessingOptions> options,
        IWebHostEnvironment environment)
    {
        _logger = logger;
        _options = options.Value;
        _environment = environment;
    }

    private string RepositoryRoot =>
        Path.GetFullPath(Path.Combine(_environment.ContentRootPath, _options.SourceDirectory));

    public void SyncRepositories(CancellationToken cancellationToken = default)
    {
        _gate.Wait(cancellationToken);
        try
        {
            SyncRepositoriesCoreAsync(cancellationToken).GetAwaiter().GetResult();
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task SyncRepositoriesCoreAsync(CancellationToken cancellationToken)
    {
        var root = RepositoryRoot;
        Directory.CreateDirectory(root);

        try
        {
            await SyncRepoAsync(
                repoName: "ruleset.skk.moe",
                url: SkkRepo,
                sparsePaths: ["Clash", "List"],
                cancellationToken);

            await SyncRepoAsync(
                repoName: "ios_rule_script",
                url: BlackmatrixRepo,
                sparsePaths: ["rule/Clash", "rule/Surge"],
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Ruleset repository sync failed. Clearing {Root}", root);
            ClearRepositoryRoot(root);
            throw;
        }
    }

    private async Task SyncRepoAsync(
        string repoName,
        Uri url,
        string[] sparsePaths,
        CancellationToken cancellationToken)
    {
        var root = RepositoryRoot;
        var target = Path.Combine(root, repoName);
        var gitDir = Path.Combine(target, ".git");

        if (Directory.Exists(gitDir))
        {
            _logger.LogInformation("Updating {Repo} via git pull.", repoName);
            try
            {
                await RunGitAsync(target, "pull --ff-only", cancellationToken);
                return;
            }
            catch (Exception ex) when (ex is InvalidOperationException)
            {
                _logger.LogWarning(ex, "git pull failed for {Repo}. Re-cloning repository.", repoName);
                DeleteDirectoryIfExists(target);
            }
        }

        await CloneRepoAsync(repoName, url, target, sparsePaths, cancellationToken);
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }

    private async Task RunGitAsync(string workingDirectory, string arguments, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "git",
            Arguments = arguments,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        startInfo.Environment["GIT_TERMINAL_PROMPT"] = "0";
        startInfo.Environment["GIT_ASKPASS"] = "echo";

        using var process = Process.Start(startInfo);
        if (process == null)
        {
            throw new InvalidOperationException("Failed to start git process.");
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken);

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"git {arguments} failed in {workingDirectory} (exit {process.ExitCode}).\n{stdout}\n{stderr}");
        }
    }

    private void ClearRepositoryRoot(string root)
    {
        try
        {
            DeleteDirectoryIfExists(root);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to clear repository root {Root}", root);
        }
        finally
        {
            Directory.CreateDirectory(root);
        }
    }

    private async Task CloneRepoAsync(
        string repoName,
        Uri url,
        string target,
        string[] sparsePaths,
        CancellationToken cancellationToken)
    {
        DeleteDirectoryIfExists(target);

        _logger.LogInformation("Cloning {Repo} with sparse checkout.", repoName);

        await RunGitAsync(RepositoryRoot, $"clone --filter=blob:none --no-checkout {Quote(url.ToString())} {Quote(target)}", cancellationToken);
        await RunGitAsync(target, "sparse-checkout init --cone", cancellationToken);
        await RunGitAsync(target, $"sparse-checkout set {string.Join(' ', sparsePaths.Select(Quote))}", cancellationToken);
        await RunGitAsync(target, "checkout", cancellationToken);
    }

    private void DeleteDirectoryIfExists(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, recursive: true);
            return;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete {Path} in one pass. Retrying entry-by-entry.", path);
        }

        try
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(path))
            {
                try
                {
                    if (Directory.Exists(entry))
                    {
                        Directory.Delete(entry, recursive: true);
                    }
                    else
                    {
                        File.Delete(entry);
                    }
                }
                catch
                {
                    // best effort
                }
            }

            Directory.Delete(path, recursive: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove directory {Path}", path);
            throw;
        }
    }
}
