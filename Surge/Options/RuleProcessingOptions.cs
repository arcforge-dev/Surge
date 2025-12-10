using System.ComponentModel.DataAnnotations;

namespace Surge.Options;

public sealed class RuleProcessingOptions
{
    [Required]
    public string SourceDirectory { get; set; } = "../RuleSet/ios_rule_script";

    [Required]
    public string OutputSubdirectory { get; set; } = "ruleset";

    [Range(1, 365)]
    public int IntervalDays { get; set; } = 7;

    public bool RunOnStartup { get; set; } = true;
}
