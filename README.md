
# CrowdStrike Incident Tracker Ready Queries

A collection of queries designed to normalize security telemetry into a format that can be directly used with the [CrowdStrike Incident Response Tracker](https://www.crowdstrike.com/en-us/blog/crowdstrike-releases-digital-forensics-and-incident-response-tracker/).

## Purpose

The CrowdStrike Incident Response Tracker is a useful spreadsheet for managing true positive investigations, especially when evidence spans multiple data sources or involves multiple systems and users. It provides a centralized source of truth and a standardized timeline that helps analysts understand event sequences and identify gaps in analysis.

This repository contains queries (primarily KQL and similar languages) that extract high-signal fields from common security platforms and format them so the results can be easily copied into the Tracker. The goal is to reduce manual formatting work during investigations and make timeline construction faster and more consistent.

## Available Query Pages

| Tool | Page |
|------|------|
| Microsoft Defender for Endpoint (KQL) | [Microsoft-Defender-for-Endpoint.md](https://github.com/Mimikatz2DA/CrowdStrike-Incident-Tracker-Ready-Queries/blob/main/Microsoft-Defender-for-Endpoint.md) |
| CrowdStrike Falcon (CQL) | Pending Creation |
## Roadmap

New queries are being added regularly across additional platforms and data sources. Planned additions include more Microsoft Defender tables, CrowdStrike Falcon, endpoint-based collection queries, and log file/directory parsers that produce Tracker-ready output.

## Contributing

Contributions are welcome. If you have a query that maps well to the Tracker format, feel free to open a pull request or issue.

## Related

- [CrowdStrike Incident Response Tracker (Original Blog Post)](https://www.crowdstrike.com/en-us/blog/crowdstrike-releases-digital-forensics-and-incident-response-tracker/)
