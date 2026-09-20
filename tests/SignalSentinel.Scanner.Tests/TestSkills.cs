using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Tests;

/// <summary>Shared minimal <see cref="SkillDefinition"/> factory for skill-focused tests.</summary>
internal static class TestSkills
{
    internal static SkillDefinition MakeSkill(string name, string body) =>
        new()
        {
            Name = name,
            InstructionsBody = body,
            RawContent = body,
            FilePath = $"/skills/{name}/SKILL.md"
        };
}
