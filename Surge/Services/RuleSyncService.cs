using LibGit2Sharp;
using LibGit2Sharp.Handlers;
using Microsoft.Extensions.Options;
using Surge.Options;

namespace Surge.Services;

public sealed class RuleSyncService(IOptionsMonitor<RuleSyncOptions> options) : BackgroundService
{
    private readonly PeriodicTimer _timer = new(TimeSpan.FromMinutes(options.CurrentValue.SyncIntervalMinutes));
    private readonly RuleSyncOptions _options = options.CurrentValue;
    private readonly string _localPath = Path.GetFullPath(options.CurrentValue.LocalDirectory);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var container = Path.GetDirectoryName(_localPath);
        if (!string.IsNullOrEmpty(container))
        {
            Directory.CreateDirectory(container);
        }

        do
        {
            try
            {
                await SyncRepositoryAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        } while (await _timer.WaitForNextTickAsync(stoppingToken));
    }

    private Task SyncRepositoryAsync(CancellationToken token)
    {
        if (!Repository.IsValid(_localPath))
        {
            ResetWorkingDirectory();
            CloneRepository();
            return Task.CompletedTask;
        }

        using var repo = new Repository(_localPath);
        var remote = repo.Network.Remotes["origin"] ?? throw new InvalidOperationException("Missing origin remote");
        var fetchOptions = CreateFetchOptions();
        Commands.Fetch(repo, remote.Name, remote.FetchRefSpecs.Select(r => r.Specification), fetchOptions, null);

        var branch = EnsureLocalBranch(repo);
        Commands.Checkout(repo, branch);
        var tracked = branch.TrackedBranch ?? repo.Branches[$"origin/{_options.Branch}"] ?? throw new InvalidOperationException("Missing tracked branch");
        repo.Reset(ResetMode.Hard, tracked.Tip);

        return Task.CompletedTask;
    }

    private void ResetWorkingDirectory()
    {
        if (Directory.Exists(_localPath))
        {
            Directory.Delete(_localPath, recursive: true);
        }
    }

    private void CloneRepository()
    {
        var cloneOptions = new CloneOptions
        {
            BranchName = _options.Branch
        };
        cloneOptions.FetchOptions.CredentialsProvider = CreateCredentialsProvider();

        Repository.Clone(_options.RepositoryUrl, _localPath, cloneOptions);

        using var repo = new Repository(_localPath);
        var branch = EnsureLocalBranch(repo);
        Commands.Checkout(repo, branch);
    }

    private Branch EnsureLocalBranch(Repository repo)
    {
        var local = repo.Branches[_options.Branch];
        if (local is not null)
        {
            EnsureTracking(repo, local);
            return local;
        }

        var origin = repo.Branches[$"origin/{_options.Branch}"] ?? throw new InvalidOperationException("Missing origin branch");
        local = repo.CreateBranch(_options.Branch, origin.Tip);
        repo.Branches.Update(local, b => b.TrackedBranch = origin.CanonicalName);
        return local;
    }

    private void EnsureTracking(Repository repo, Branch branch)
    {
        if (branch.TrackedBranch is null)
        {
            var origin = repo.Branches[$"origin/{_options.Branch}"] ?? throw new InvalidOperationException("Missing origin branch");
            repo.Branches.Update(branch, b => b.TrackedBranch = origin.CanonicalName);
        }
    }

    private FetchOptions CreateFetchOptions() => new() { CredentialsProvider = CreateCredentialsProvider() };

    private CredentialsHandler CreateCredentialsProvider()
    {
        return (_url, _user, _types) =>
        {
            if (!string.IsNullOrWhiteSpace(_options.Auth.Username) && !string.IsNullOrWhiteSpace(_options.Auth.Password))
            {
                return new UsernamePasswordCredentials
                {
                    Username = _options.Auth.Username,
                    Password = _options.Auth.Password
                };
            }

            return new DefaultCredentials();
        };
    }

    public override void Dispose()
    {
        _timer.Dispose();
        base.Dispose();
    }
}
