# Microsoft Defender for Endpoint (MDE) Queries

## Purpose

This page contains KQL queries designed to populate the CrowdStrike Incident Response Tracker using Microsoft Defender for Endpoint advanced hunting tables. Each query is structured to extract high-signal fields and format them for direct use in the tracker’s Timeline, Systems, Accounts, Host Indicators, and Network Indicators tabs.

The queries prioritize the most relevant context first (especially in concatenated Activity fields) and use the timestamp format `YY-MM-DDTHH-MM-SSZ`. They are intended as starting points that can be refined for specific investigations.

---

## DeviceProcessEvents

```kql
// Define available time options
let LookBack = 1d;
let StartTime = datetime(2026-08-01);
let EndTime = datetime(2026-08-03);
// Define tracker and investigation values
let SubmittedByValue = "<Analyst Name>";
let ComputerNameValue = "<DeviceName>";
let UserName = "<AccountName>";
// Define strings to search for
let SearchTerms = dynamic([
    "curl",
    "powershell"
]);
// Search Microsoft Defender process creation telemetry
DeviceProcessEvents
// Relative time option
| where Timestamp >= ago(LookBack)
// Alternate fixed time option
// Comment out the relative time filter above and uncomment this line when needed
// | where Timestamp between (StartTime .. EndTime)
// Limit results to activity associated with the specified account
| where AccountName has UserName
// Limit results to activity associated with the specified system
| where DeviceName has ComputerNameValue
// Search the referenced columns for any value in SearchTerms
| where ProcessCommandLine has_any (SearchTerms)
    or InitiatingProcessCommandLine has_any (SearchTerms)
    or FileName has_any (SearchTerms)
    or InitiatingProcessFileName has_any (SearchTerms)
    or FolderPath has_any (SearchTerms)
// Sort using the native Timestamp before project removes the field
// This ensures the newest process activity appears first
| order by Timestamp desc
// Format results using the tracker column names and order
| project
    // Analyst submitting or documenting the evidence
    SubmittedBy = SubmittedByValue,
    // Date this evidence record was added in MM/DD/YYYY format
    DateAdded = format_datetime(now(), "MM/dd/yyyy"),
    // Initial review or workflow status
    StatusTag = "Under Investigation",
    // Endpoint where the process executed
    SystemName = DeviceName,
    // UTC event timestamp including hours, minutes, and seconds
    // Example: 2026-11-16T19:45:32Z
    DateTimeUTC = strcat(
        format_datetime(Timestamp, "yyyy-MM-dd"),
        "T",
        format_datetime(Timestamp, "HH"),
        ":",
        format_datetime(Timestamp, "mm"),
        ":",
        format_datetime(Timestamp, "ss"),
        "Z"
    ),
    // Identifies the telemetry or event type
    TimestampType = "Process Creation",
    // Consolidate key process context into a single Activity field
    Activity = strcat(
        ProcessCommandLine, " | ",
        "Parent: ", InitiatingProcessFileName, " (", InitiatingProcessCommandLine, ") | ",
        "User: ", AccountName, " | ",
        "PID: ", tostring(ProcessId)
    ),
    // Defender table providing the evidence
    EvidenceSource = "MDE - DeviceProcessEvents",
    // Additional evidence details for the process executable
    DetailsComments = "",
    // Placeholder for ATT&CK technique or sub-technique
    ATTCKAlignment = "",
    // Placeholder for file size
    SizeBytes = "",
    // SHA256 of the process image when available
    Hash = SHA256,
    // Account associated with the process execution
    OwnerAccount = AccountName,
    // Placeholder for analyst observations
    Notes = ""```

## DeviceEvents

## DeviceFileEvents

## DeviceNetworkEvents
