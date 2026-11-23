using System.Xml.Linq;
using WindowsAppProtector;
using WindowsAppProtector.Services;
using Xunit;

namespace UnitTests;

public sealed class StartupServiceTests
{
    private static readonly XNamespace TaskNs = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    [Fact]
    public void BuildStartupTaskXml_Produces_WellFormed_Xml_With_Expected_Elements()
    {
        const string executablePath = @"C:\Program Files\Windows App Protector\WindowsAppProtector.exe";

        var xml = StartupService.BuildStartupTaskXml(executablePath);
        var document = XDocument.Parse(xml);

        var root = document.Root;
        Assert.NotNull(root);
        Assert.Equal(TaskNs + "Task", root!.Name);
        Assert.Equal("1.2", root.Attribute("version")?.Value);

        Assert.Equal(
            $"{ProductBrand.Name} background protection",
            root.Element(TaskNs + "RegistrationInfo")?.Element(TaskNs + "Description")?.Value);

        var logonTrigger = root.Element(TaskNs + "Triggers")?.Element(TaskNs + "LogonTrigger");
        Assert.NotNull(logonTrigger);
        Assert.Equal("true", logonTrigger!.Element(TaskNs + "Enabled")?.Value);
        Assert.False(string.IsNullOrWhiteSpace(logonTrigger.Element(TaskNs + "UserId")?.Value));

        var principal = root.Element(TaskNs + "Principals")?.Element(TaskNs + "Principal");
        Assert.NotNull(principal);
        Assert.Equal("InteractiveToken", principal!.Element(TaskNs + "LogonType")?.Value);
        Assert.Equal("HighestAvailable", principal.Element(TaskNs + "RunLevel")?.Value);

        var settings = root.Element(TaskNs + "Settings");
        Assert.NotNull(settings);
        Assert.Equal("false", settings!.Element(TaskNs + "DisallowStartIfOnBatteries")?.Value);
        Assert.Equal("false", settings.Element(TaskNs + "StopIfGoingOnBatteries")?.Value);
        Assert.Equal("PT0S", settings.Element(TaskNs + "ExecutionTimeLimit")?.Value);

        var exec = root.Element(TaskNs + "Actions")?.Element(TaskNs + "Exec");
        Assert.NotNull(exec);
        Assert.Equal(executablePath, exec!.Element(TaskNs + "Command")?.Value);
        Assert.Equal(App.BackgroundArgument, exec.Element(TaskNs + "Arguments")?.Value);
    }

    [Fact]
    public void BuildStartupTaskXml_Escapes_Special_Xml_Characters_In_Executable_Path()
    {
        const string executablePath = @"C:\Apps\Protector & Guard <v2>\WindowsAppProtector.exe";

        var xml = StartupService.BuildStartupTaskXml(executablePath);
        var document = XDocument.Parse(xml);

        var command = document.Root?
            .Element(TaskNs + "Actions")?
            .Element(TaskNs + "Exec")?
            .Element(TaskNs + "Command")?.Value;
        Assert.Equal(executablePath, command);
    }
}
