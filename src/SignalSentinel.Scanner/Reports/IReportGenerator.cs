using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Reports;

/// <summary>
/// Interface for generating scan reports in various formats.
/// </summary>
public interface IReportGenerator
{
    /// <summary>
    /// Gets the output format name.
    /// </summary>
    string Format { get; }

    /// <summary>
    /// Gets the file extension for this format.
    /// </summary>
    string FileExtension { get; }

    /// <summary>
    /// Generates a report from the scan result.
    /// </summary>
    /// <param name="result">The scan result to report on.</param>
    /// <returns>The report content as a string.</returns>
    string Generate(ScanResult result);
}
