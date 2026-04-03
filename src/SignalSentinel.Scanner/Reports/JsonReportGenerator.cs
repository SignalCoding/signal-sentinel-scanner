using System.Text.Json;
using System.Text.Json.Serialization;
using SignalSentinel.Core.Models;

namespace SignalSentinel.Scanner.Reports;

/// <summary>
/// Generates JSON format scan reports.
/// </summary>
public sealed class JsonReportGenerator : IReportGenerator
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public string Format => "JSON";
    public string FileExtension => ".json";

    public string Generate(ScanResult result)
    {
        return JsonSerializer.Serialize(result, JsonOptions);
    }
}
