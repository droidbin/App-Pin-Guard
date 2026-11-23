using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

// Runtime\status.json. Readable by standard users, so it carries app names only: no paths, no PIN data.
[DataContract]
internal sealed class StatusDocument
{
    internal const string RuleGate = "applied-gate";
    internal const string RuleBlocked = "applied-blocked";
    internal const string RuleWindow = "window-mode";
    internal const string RuleConflict = "conflict";
    internal const string RuleNone = "none";

    public StatusDocument() { Initialize(); }

    [OnDeserializing]
    private void OnDeserializing(StreamingContext context) { Initialize(); }

    private void Initialize()
    {
        SchemaVersion = 1;
        ServiceVersion = string.Empty;
        StartedAtUtc = string.Empty;
        UpdatedAtUtc = string.Empty;
        AppliedRevision = 0;
        PolicyError = null;
        Healthy = true;
        Watcher = "polling";
        Apps = new List<AppStatus>();
        Agents = new List<AgentStatus>();
        TamperEvents = new List<TamperEvent>();
    }

    [DataMember] public int SchemaVersion { get; set; }
    [DataMember] public string ServiceVersion { get; set; }
    [DataMember] public string StartedAtUtc { get; set; }
    [DataMember] public string UpdatedAtUtc { get; set; }
    [DataMember] public long AppliedRevision { get; set; }
    [DataMember] public string PolicyError { get; set; }
    [DataMember] public bool Healthy { get; set; }
    // "wmi" | "polling"
    [DataMember] public string Watcher { get; set; }
    [DataMember] public List<AppStatus> Apps { get; set; }
    [DataMember] public List<AgentStatus> Agents { get; set; }
    [DataMember] public List<TamperEvent> TamperEvents { get; set; }
}

[DataContract]
internal sealed class AppStatus
{
    [DataMember] public string Id { get; set; }
    [DataMember] public string Name { get; set; }
    // "launch" | "window"
    [DataMember] public string Mode { get; set; }
    // applied-gate | applied-blocked | window-mode | conflict | error:<code> | none
    [DataMember] public string Rule { get; set; }
    [DataMember] public string LastBlockedUtc { get; set; }
}

[DataContract]
internal sealed class AgentStatus
{
    [DataMember] public int Session { get; set; }
    // running | restarting | failed
    [DataMember] public string State { get; set; }
    [DataMember] public int Restarts { get; set; }
}

[DataContract]
internal sealed class TamperEvent
{
    [DataMember] public string AtUtc { get; set; }
    [DataMember] public string Detail { get; set; }
}
