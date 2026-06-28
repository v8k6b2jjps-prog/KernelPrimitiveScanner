# 🛡️ BYOVD Kernel Primitive Scanner

A high-fidelity defensive security and forensic triage utility designed to identify Bring Your Own Vulnerable Driver (BYOVD) threats. The utility performs deep structural parsing of Portable Executable (PE) headers and maps the Import Address Table (IAT) of Windows driver files (`.sys`) to flag dangerous kernel-mode primitives commonly weaponized by threat actors to blind security agents, bypass Windows Kernel Driver Signing Policy (kmci), and achieve arbitrary Ring 0 memory execution.

---

## 🚀 Core Capabilities

*   **🔍 Low-Level PE Structural Auditing:** Programmatically walks the DOS header, validates the NT signature, calculates section alignments dynamically, and walks the Data Directories to pull raw imports directly out of the file layout without relying on fragile system utilities or external binary dependencies.
*   **💻 Bi-Directional Architecture Support:** Fully compatible with both 32-bit (`I386`) and 64-bit (`AMD64`) kernel modules via runtime dynamic type alignment matching the target binary's structural architecture.
*   **🧼 Noise Reduction & Vendor Filtering:** Automatically excludes standard Microsoft-signed binaries from the final report by inspecting metadata attributes, allowing security engineers to instantly focus triage efforts purely on third-party signed driver packages.
*   **📊 Cryptographic & Forensic Telemetry:** Generates actionable indicator data on demand, combining file structural properties, publisher records, functional descriptions, and cryptographic SHA256 hashes for immediate SIEM ingestion or threat intelligence lookup.

---

## 🧠 Primitive Threat Score (PTS) System

*  **📊 Quantitative Risk Assessment:** Calculates a standardized risk metric from 0 to 10 by performing a weighted analysis of imported kernel-mode primitives, allowing security teams to immediately prioritize forensic triage based on the identified exploit vectors.
*  **⚖️ Weighted Abuse Profiling:** Assigns distinct severity values to primitives based on their potential for weaponization, with critical weightings for routines capable of security callback blinding, physical memory manipulation, and direct hardware interaction.
*  **🔍 Risk-Based Filtering:** Enables automated triage workflows by utilizing a configurable threshold system, ensuring that analysts focus exclusively on high-risk binaries that meet or exceed predefined critical danger levels.
*  **📈 Severity Categorization:** Provides immediate operational insight by mapping raw technical findings into actionable risk tiers: 0 (Safe/Standard), 1–3 (Low Risk), 4–7 (Elevated Risk), and 8–10 (Critical Risk), facilitating rapid incident response and binary isolation.

---

## 🎯 Targeted Kernel Primitives

### ⚡ Basic Mode (High-Severity Abuse Vectors)
*   **🧠 Arbitrary Physical Mapping:** Detection of functions like `MmMapIoSpace`, `MmMapIoSpaceEx`, `ZwMapViewOfSection`, and `NtMapViewOfSection` used to bypass page table protections and manipulate physical memory directly.
*   **📝 Kernel Memory Copying:** Flagging `MmCopyVirtualMemory` and `MmCopyMemory` routines which allow cross-process address manipulation from userland into kernel-space.
*   **⚙️ CPU Control Register Manipulation:** Auditing low-level intrinsics like `__writemsr`, `__writecr3`, and `__writecr4` that can be hijacked to mask execution paths, compromise hardware page isolation, or completely disable kernel protections.
*   **❌ Aggressive Process Blinding:** Spotting the direct imports of `ZwTerminateProcess` and `NtTerminateProcess` used by rootkits to kill active Endpoint Detection and Response (EDR) or Antivirus processes from the highest privilege ring.

### 🧪 Extended Mode (Advanced Rootkit & Blinding Behaviors)
*   **💾 Alternative Memory Allocations:** Extends the detection logic to monitor advanced page pinning, address space translations, and memory mapping mechanisms such as `MmMapLockedPagesSpecifyCache` or pool allocations like `ExAllocatePool2`.
*   **🔌 Direct Hardware I/O Interaction:** Flags legacy and microcode-level operations including direct port writes (`WRITE_PORT_UCHAR`, `WRITE_PORT_ULONG`) which can bypass traditional OS abstractions.
*   **🙈 Security Callback Blinding:** Detects infrastructure-level routine manipulation functions such as `CmUnRegisterCallback`, `ObUnRegisterCallbacks`, and `PsSetCreateProcessNotifyRoutineEx` which are actively abused by offensive tools to strip system callbacks and effectively blind the host EDR telemetry stream.

---

## 📂 Execution Vectors & Defaults

When run with standard configurations, the scanner acts as an automated wide-spectrum hunter, recursively examining the primary paths where third-party software places kernel-mode execution packages:
*   📁 `C:\Windows\System32`
*   📁 `C:\Windows\System32\drivers`
*   📁 `C:\Program Files`
*   📁 `C:\Program Files (x86)`

---

## ⚙️ Parameters Reference

*   **🛠️ `System32`**: Limits scope strictly to core local configuration binaries inside the System32 directory.
*   **🗄️ `Drivers`**: Targets the active kernel driver repository folder explicitly.
*   **💻 `ProgramFiles`**: Sweeps local software installation targets for userland-dropped third-party driver packages.
*   **🎯 `CustomPath`**: Overrides default sweep behavior to execute localized forensic operations against a specified folder or staging root.
*   **⏹️ `NoRecurse`**: Restricts the folder parser to the top-level directory context, skipping deeply nested directory layers.
*   **🔓 `IncludeAll`**: Disables the Microsoft vendor suppression filter, enabling a complete system-wide baseline report.
*   **🛡️ `ValidateLolDrivers`**: Cross-references discovered drivers against the Living Off the Land Drivers (LOLDrivers) database to flag known vulnerable or malicious binaries.
*   **📜 `ValidateMSBlockPolicy`**: Checks system drivers against the official Microsoft Recommended Driver Block Rules to ensure compliance with enterprise-grade hardening policies.
*   **🔍 `ScanMode`**: Configures the underlying dictionary assessment architecture to run in either `Basic` triage mode or the comprehensive `Extended` hunting mode.

## 💻 Production Triage & Threat Hunting Examples

### 🎯 Scenario 1: Proactive Enterprise Thread Hunt (Userland Focus)
Sweeps high-risk endpoint software installations (browsers, local database tools, VPN clients) using aggressive runtime assessment rules. It pairs the high-fidelity deep engine with the online Living Off the Land Drivers database to immediately isolate known leaked or vulnerable third-party binaries.

*   ⚡ Velocity Expectation: Moderate to slow depending on disk size.
*   📡 Telemetry Output: High density structural matches and SHA256 hashes.

Scan-DriverPrimitive -ProgramFiles -ScanMode Extended -ValidateLolDrivers -IncludeAll


### 🛡️ Scenario 2: Rapid Automated Tier-1 Triage (Core OS Assets)
Executes a highly lightweight baseline assessment optimized for rapid incident management playbooks or automated CI pipeline integrity tests. It validates the local System32 directory structures strictly against the hardware enforcement driver blocklist configuration provided by Microsoft, suppressing verified vendor signatures to keep output signal-to-noise ratios crisp.

*   ⚡ Velocity Expectation: Rapid (typically under 60 seconds).
*   📡 Telemetry Output: Low density, exception-only alerts flagging hardening non-compliance.

Scan-DriverPrimitive -System32 -ScanMode Basic -ValidateMSBlockPolicy


### 🧪 Scenario 3: Targeted Post-Exploitation Forensic IR Sweep
Designed for point-in-time dead-box triage when a security analyst isolates a specific payload drop zone or a non-standard application execution directory. This configuration enforces rigid operational boundaries by explicitly disabling multi-layer file tree recursion, ensuring your hunting actions remain targeted, predictable, and clean.

*   ⚡ Velocity Expectation: Instantaneous.
*   📡 Telemetry Output: Full metadata and raw Import Address Table (IAT) primitive analysis of the targeted folder.

Scan-DriverPrimitive -CustomPath "C:\Forensics\Staging\MalwareDrop" -NoRecurse -ScanMode Extended -IncludeAll


### 📊 Scenario 4: Wide-Spectrum Baseline Extraction (Gold Image Auditing)
Sweeps both standard system repositories and userland application folders simultaneously. This wide-spectrum configuration bypasses traditional vendor suppression rules to output a complete inventory of every non-Microsoft kernel driver asset present across the host, establishing a definitive forensic golden baseline.

*   ⚡ Velocity Expectation: Slow, exhaustive drive-wide interrogation.
*   📡 Telemetry Output: Comprehensive CSV or JSON telemetry dataset containing every third-party cryptographic and PE metadata asset discovered.

Scan-DriverPrimitive -System32 -Drivers -ProgramFiles -ScanMode Extended -IncludeAll
