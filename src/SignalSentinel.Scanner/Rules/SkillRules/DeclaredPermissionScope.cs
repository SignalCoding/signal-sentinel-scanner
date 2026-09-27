// -----------------------------------------------------------------------
// <copyright file="DeclaredPermissionScope.cs" company="Signal Coding Limited">
//     Copyright 2026 Signal Coding Limited. All rights reserved.
//     Licensed under the Apache License, Version 2.0.
// </copyright>
// -----------------------------------------------------------------------

namespace SignalSentinel.Scanner.Rules.SkillRules;

/// <summary>
/// v3.1.1 (R1, ss017-scoped-declarations): shared reads of a declared
/// list-shaped permission scope (e.g. <c>files.write</c>, <c>network.allow</c>),
/// used by both <see cref="SkillExcessivePermRule"/> (SS-017) and
/// <see cref="SkillScopeViolationRule"/> (SS-012) so the two rules agree on
/// what "declared" means for the same frontmatter shape. Previously each rule
/// carried its own byte-identical copy of <see cref="HasNonEmptyDeclaredScope"/>.
/// </summary>
internal static class DeclaredPermissionScope
{
    /// <summary>
    /// A declared list-shaped scope (e.g. <c>files.write</c>, <c>network.allow</c>)
    /// counts as declared only when it is genuinely non-empty once its list
    /// punctuation is stripped - an explicitly empty declared scope (<c>[]</c>)
    /// declares no egress/write access, which is the opposite of a grant.
    /// </summary>
    internal static bool HasNonEmptyDeclaredScope(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var trimmed = value.Trim().TrimStart('[').TrimEnd(']').Trim();
        return trimmed.Length > 0;
    }

    /// <summary>
    /// v3.1.1 (R1): a declared list-shaped scope raises SS-017's implied risk
    /// floor only when at least one of its entries is unbounded, as judged by
    /// <paramref name="isUnboundedEntry"/>. An enumerated list of concrete,
    /// scoped values (a single named host, a single relative path) is a
    /// narrower and more honest declaration than a boolean grant and must not
    /// be treated the same as one. An empty or absent declaration is never
    /// unbounded - it declares nothing.
    /// </summary>
    internal static bool HasUnboundedEntry(string? value, Func<string, bool> isUnboundedEntry)
    {
        if (!HasNonEmptyDeclaredScope(value)) return false;

        var trimmed = value!.Trim().TrimStart('[').TrimEnd(']').Trim();
        foreach (var rawEntry in trimmed.Split(','))
        {
            var entry = rawEntry.Trim().Trim('"', '\'');
            if (entry.Length > 0 && isUnboundedEntry(entry))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// v3.1.1 (R1): an unbounded <c>network.allow</c> entry - a blanket
    /// wildcard (<c>*</c>), the all-addresses CIDR blocks, a bare wildcard
    /// scheme (<c>http://*</c>), or a wildcard domain (<c>*.example.com</c>).
    /// The wildcard-domain case is treated as unbounded rather than "narrower
    /// than *": a DNS wildcard resolves to any subdomain the operator
    /// controls, so it does not meaningfully bound the egress surface for the
    /// purposes of this check.
    /// </summary>
    internal static bool IsUnboundedNetworkEntry(string entry) =>
        entry.Contains('*', StringComparison.Ordinal) ||
        string.Equals(entry, "0.0.0.0/0", StringComparison.Ordinal) ||
        string.Equals(entry, "::/0", StringComparison.Ordinal);

    /// <summary>
    /// v3.1.1 (R1): an unbounded <c>files.write</c> entry - a wildcard, the
    /// filesystem root, the user's home directory, or a path that escapes the
    /// skill's own directory via <c>..</c>. An enumerated relative path
    /// (<c>reports/summary.md</c>) is bounded.
    /// </summary>
    internal static bool IsUnboundedFilesWriteEntry(string entry) =>
        entry.Contains('*', StringComparison.Ordinal) ||
        string.Equals(entry, "/", StringComparison.Ordinal) ||
        string.Equals(entry, "~", StringComparison.Ordinal) ||
        entry.Contains("..", StringComparison.Ordinal);

    /// <summary>
    /// v3.1.1 (R1 extension, found necessary by the AST06 V3/C4 corpus pair):
    /// an unbounded <c>shell.commands</c> entry - a wildcard. A non-empty,
    /// concrete <c>shell.commands</c> allow-list (Universal Skill Format's
    /// <c>permissions.shell.commands</c>) bounds an otherwise-generic shell
    /// grant to specific executables, the same way an enumerated
    /// <c>network.allow</c>/<c>files.write</c> list bounds those.
    /// </summary>
    internal static bool IsUnboundedShellCommandEntry(string entry) =>
        entry.Contains('*', StringComparison.Ordinal);
}
