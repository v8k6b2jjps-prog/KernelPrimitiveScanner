# BYOVD File Scanner

A PowerShell security utility designed to scan directories for Bring Your Own Vulnerable Driver (BYOVD) vulnerabilities. It parses the Import Address Table (IAT) of Portable Executable (PE) driver files to detect highly abused kernel primitives.

## Features
- Inspects both 32-bit and 64-bit driver structures by directly parsing the PE headers.
- Identifies critical Ring 0 exploitation primitives including physical memory mapping, direct kernel copying, CPU register modifications, and process termination.
- Offers two scanning depths: Basic (most common abuse targets) and Extended (rootkit-style security callback removal, hardware port I/O, and advanced mapping).
- Automatically filters out legitimate Microsoft drivers by default to keep the focus strictly on potential third-party risks.
- Collects crucial telemetry including file descriptions, company signatures, and SHA256 hashes for immediate threat intelligence cross-referencing.

## Monitored Directories
By default, the script scans the most vulnerable storage points for third-party kernel code:
- C:\Windows\System32
- C:\Windows\System32\drivers
- C:\Program Files
- C:\Program Files (x86)

## Parameters
- System32: Audits the System32 directory exclusively.
- Drivers: Audits the drivers directory exclusively.
- ProgramFiles: Focuses entirely on user-installed application paths.
- CustomPath: Restricts execution to a user-provided target directory.
- NoRecurse: Disables recursive deep-folder checking.
- IncludeAll: Disables vendor filtering to include Microsoft-signed modules in the report.
- ScanMode: Toggles the definition lookup list between 'Basic' and 'Extended'.
