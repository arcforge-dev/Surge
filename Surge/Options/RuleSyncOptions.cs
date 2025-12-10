using System;
using System.ComponentModel.DataAnnotations;

namespace Surge.Options;

public sealed class RuleSyncOptions
{
    [Required]
    public string RepositoryUrl { get; set; } = "https://github.com/arcforge-dev/ios_rule_script.git";

    [Required]
    public string Branch { get; set; } = "master";

    [Required]
    public string LocalDirectory { get; set; } = "../RuleSet/ios_rule_script";

    [Range(5, 1440)]
    public int SyncIntervalMinutes { get; set; } = 180;

    public AuthOptions Auth { get; set; } = new();
}

public sealed class AuthOptions
{
    public string? Username { get; set; } = Environment.GetEnvironmentVariable("RULESET_GIT_USERNAME");
    public string? Password { get; set; } = Environment.GetEnvironmentVariable("RULESET_GIT_PASSWORD");
}
