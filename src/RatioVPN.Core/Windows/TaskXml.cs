using System.Xml.Linq;

namespace RatioVPN.Core.Windows;

/// <summary>Liest die Ausgabe von <c>schtasks /Query /XML</c> (plattformneutral, nur Text).</summary>
public static class TaskXml
{
    /// <summary>Programmpfad der ersten Exec-Aktion (ohne Anführungszeichen) oder null.</summary>
    public static string? CommandPath(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) return null;
        try
        {
            var doc = XDocument.Parse(xml);
            var cmd = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Command")?.Value.Trim();
            if (string.IsNullOrEmpty(cmd)) return null;
            return Environment.ExpandEnvironmentVariables(cmd.Trim('"'));
        }
        catch (System.Xml.XmlException)
        {
            return null;
        }
    }
}
