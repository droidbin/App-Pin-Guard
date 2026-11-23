using System;
using System.IO;

internal static class WapPaths
{
    internal const string DataFolderName = "Windows App Protector";
    internal const string ServiceName = "WindowsAppProtectorService";
    internal const string ServiceExeName = "WindowsAppProtector.Service.exe";
    internal const string UiExeName = "WindowsAppProtector.WinUI.exe";
    internal const string GateExeName = "WindowsAppProtector.Gate.exe";
    internal const string AgentExeName = "WindowsAppProtector.WindowAgent.exe";

    internal const string PolicyChangedEvent = @"Global\WAP.PolicyChanged";
    internal const string EnforcementChangedEvent = @"Global\WAP.EnforcementChanged";
    internal const string AgentStopEvent = @"Global\WAP.AgentStop";
    internal const string PolicyWriteMutex = @"Global\WAP.PolicyWrite";

    internal static string Root
    {
        get
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), DataFolderName);
        }
    }

    internal static string PolicyFile { get { return Path.Combine(Root, "policy.json"); } }
    internal static string SecretsFile { get { return Path.Combine(Root, "secrets.json"); } }
    internal static string UiSettingsFile { get { return Path.Combine(Root, "ui.json"); } }
    internal static string LegacyConfigFile { get { return Path.Combine(Root, "config.json"); } }
    internal static string LegacyConfigBackup { get { return Path.Combine(Root, "config.json.v2.bak"); } }
    internal static string LegacyPolicyFolder { get { return Path.Combine(Root, "Policy"); } }

    internal static string RuntimeDir { get { return Path.Combine(Root, "Runtime"); } }
    internal static string EnforcementFile { get { return Path.Combine(RuntimeDir, "enforcement.txt"); } }
    internal static string StatusFile { get { return Path.Combine(RuntimeDir, "status.json"); } }
    internal static string AttemptsDir { get { return Path.Combine(RuntimeDir, "attempts"); } }

    internal static string GateDir { get { return Path.Combine(Root, "Gate"); } }
    internal static string RequestsDir { get { return Path.Combine(GateDir, "Requests"); } }
    internal static string ResponsesDir { get { return Path.Combine(GateDir, "Responses"); } }

    internal static string LogsDir { get { return Path.Combine(Root, "Logs"); } }

    // Per-user logs written by processes that run in a user session without write access to ProgramData.
    internal static string UserLogsDir
    {
        get
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WindowsAppProtector.WinUI", "Logs");
        }
    }

    internal static string UserDataDir
    {
        get
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WindowsAppProtector.WinUI");
        }
    }

    internal static string LegacyUserPinFile { get { return Path.Combine(UserDataDir, "pin.json"); } }

    internal static string LegacyUserConfigFile
    {
        get
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "WindowsAppProtector.WinUI", "config.json");
        }
    }
}
