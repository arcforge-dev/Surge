namespace Surge.Options;

using System.ComponentModel.DataAnnotations;

public sealed class RuleProcessingOptions {
    [Required]
    public string SourceDirectory { get; set; } = "../RuleSet";

    [Required]
    public string OutputSubdirectory { get; set; } = "ruleset";

    [Range(1, 365)]
    public int IntervalDays { get; set; } = 7;

    public bool RunOnStartup { get; set; } = true;
}
