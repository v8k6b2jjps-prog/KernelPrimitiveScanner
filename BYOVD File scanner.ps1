using namespace System.IO
using namespace System.Net
using namespace System.Web
using namespace System.Numerics
using namespace System.Security.Cryptography
using namespace System.Collections.Generic
using namespace System.Drawing
using namespace System.IO.Compression
using namespace System.Management.Automation
using namespace System.Net
using namespace System.Diagnostics
using namespace System.Reflection
using namespace System.Reflection.Emit
using namespace System.Runtime.InteropServices
using namespace System.Security.AccessControl
using namespace System.Security.Principal
using namespace System.ServiceProcess
using namespace System.Text
using namespace System.Text.RegularExpressions
using namespace System.Threading
using namespace System.Windows.Forms

if (!([PSTypeName]'PE').Type) {
$code = @"
using System;
using System.Runtime.InteropServices;

public class PE
{
    [Flags]
    public enum IMAGE_DOS_SIGNATURE : ushort
    {
        DOS_SIGNATURE = 0x5A4D, // MZ
        OS2_SIGNATURE = 0x454E, // NE
        OS2_SIGNATURE_LE = 0x454C, // LE
        VXD_SIGNATURE = 0x454C, // LE
    }
        
    [Flags]
    public enum IMAGE_NT_SIGNATURE : uint
    {
        VALID_PE_SIGNATURE = 0x00004550 // PE00
    }
        
    [Flags]
    public enum IMAGE_FILE_MACHINE : ushort
    {
        UNKNOWN = 0,
        I386 = 0x014c, // Intel 386.
        R3000 = 0x0162, // MIPS little-endian =0x160 big-endian
        R4000 = 0x0166, // MIPS little-endian
        R10000 = 0x0168, // MIPS little-endian
        WCEMIPSV2 = 0x0169, // MIPS little-endian WCE v2
        ALPHA = 0x0184, // Alpha_AXP
        SH3 = 0x01a2, // SH3 little-endian
        SH3DSP = 0x01a3,
        SH3E = 0x01a4, // SH3E little-endian
        SH4 = 0x01a6, // SH4 little-endian
        SH5 = 0x01a8, // SH5
        ARM = 0x01c0, // ARM Little-Endian
        THUMB = 0x01c2,
        ARMNT = 0x01c4, // ARM Thumb-2 Little-Endian
        AM33 = 0x01d3,
        POWERPC = 0x01F0, // IBM PowerPC Little-Endian
        POWERPCFP = 0x01f1,
        IA64 = 0x0200, // Intel 64
        MIPS16 = 0x0266, // MIPS
        ALPHA64 = 0x0284, // ALPHA64
        MIPSFPU = 0x0366, // MIPS
        MIPSFPU16 = 0x0466, // MIPS
        AXP64 = ALPHA64,
        TRICORE = 0x0520, // Infineon
        CEF = 0x0CEF,
        EBC = 0x0EBC, // EFI public byte Code
        AMD64 = 0x8664, // AMD64 (K8)
        M32R = 0x9041, // M32R little-endian
        CEE = 0xC0EE
    }
        
    [Flags]
    public enum IMAGE_FILE_CHARACTERISTICS : ushort
    {
        IMAGE_RELOCS_STRIPPED = 0x0001, // Relocation info stripped from file.
        IMAGE_EXECUTABLE_IMAGE = 0x0002, // File is executable (i.e. no unresolved external references).
        IMAGE_LINE_NUMS_STRIPPED = 0x0004, // Line nunbers stripped from file.
        IMAGE_LOCAL_SYMS_STRIPPED = 0x0008, // Local symbols stripped from file.
        IMAGE_AGGRESIVE_WS_TRIM = 0x0010, // Agressively trim working set
        IMAGE_LARGE_ADDRESS_AWARE = 0x0020, // App can handle >2gb addresses
        IMAGE_REVERSED_LO = 0x0080, // public bytes of machine public ushort are reversed.
        IMAGE_32BIT_MACHINE = 0x0100, // 32 bit public ushort machine.
        IMAGE_DEBUG_STRIPPED = 0x0200, // Debugging info stripped from file in .DBG file
        IMAGE_REMOVABLE_RUN_FROM_SWAP = 0x0400, // If Image is on removable media =copy and run from the swap file.
        IMAGE_NET_RUN_FROM_SWAP = 0x0800, // If Image is on Net =copy and run from the swap file.
        IMAGE_SYSTEM = 0x1000, // System File.
        IMAGE_DLL = 0x2000, // File is a DLL.
        IMAGE_UP_SYSTEM_ONLY = 0x4000, // File should only be run on a UP machine
        IMAGE_REVERSED_HI = 0x8000 // public bytes of machine public ushort are reversed.
    }
        
    [Flags]
    public enum IMAGE_NT_OPTIONAL_HDR_MAGIC : ushort
    {
        PE32 = 0x10b,
        PE64 = 0x20b
    }
        
    [Flags]
    public enum IMAGE_SUBSYSTEM : ushort
    {
        UNKNOWN = 0, // Unknown subsystem.
        NATIVE = 1, // Image doesn't require a subsystem.
        WINDOWS_GUI = 2, // Image runs in the Windows GUI subsystem.
        WINDOWS_CUI = 3, // Image runs in the Windows character subsystem.
        OS2_CUI = 5, // image runs in the OS/2 character subsystem.
        POSIX_CUI = 7, // image runs in the Posix character subsystem.
        NATIVE_WINDOWS = 8, // image is a native Win9x driver.
        WINDOWS_CE_GUI = 9, // Image runs in the Windows CE subsystem.
        EFI_APPLICATION = 10,
        EFI_BOOT_SERVICE_DRIVER = 11,
        EFI_RUNTIME_DRIVER = 12,
        EFI_ROM = 13,
        XBOX = 14,
        WINDOWS_BOOT_APPLICATION = 16
    }
        
    [Flags]
    public enum IMAGE_DLLCHARACTERISTICS : ushort
    {
        DYNAMIC_BASE = 0x0040, // DLL can move.
        FORCE_INTEGRITY = 0x0080, // Code Integrity Image
        NX_COMPAT = 0x0100, // Image is NX compatible
        NO_ISOLATION = 0x0200, // Image understands isolation and doesn't want it
        NO_SEH = 0x0400, // Image does not use SEH. No SE handler may reside in this image
        NO_BIND = 0x0800, // Do not bind this image.
        WDM_DRIVER = 0x2000, // Driver uses WDM model
        TERMINAL_SERVER_AWARE = 0x8000
    }
        
    [Flags]
    public enum IMAGE_SCN : uint
    {
        TYPE_NO_PAD = 0x00000008, // Reserved.
        CNT_CODE = 0x00000020, // Section contains code.
        CNT_INITIALIZED_DATA = 0x00000040, // Section contains initialized data.
        CNT_UNINITIALIZED_DATA = 0x00000080, // Section contains uninitialized data.
        LNK_INFO = 0x00000200, // Section contains comments or some other type of information.
        LNK_REMOVE = 0x00000800, // Section contents will not become part of image.
        LNK_COMDAT = 0x00001000, // Section contents comdat.
        NO_DEFER_SPEC_EXC = 0x00004000, // Reset speculative exceptions handling bits in the TLB entries for this section.
        GPREL = 0x00008000, // Section content can be accessed relative to GP
        MEM_FARDATA = 0x00008000,
        MEM_PURGEABLE = 0x00020000,
        MEM_16BIT = 0x00020000,
        MEM_LOCKED = 0x00040000,
        MEM_PRELOAD = 0x00080000,
        ALIGN_1BYTES = 0x00100000,
        ALIGN_2BYTES = 0x00200000,
        ALIGN_4BYTES = 0x00300000,
        ALIGN_8BYTES = 0x00400000,
        ALIGN_16BYTES = 0x00500000, // Default alignment if no others are specified.
        ALIGN_32BYTES = 0x00600000,
        ALIGN_64BYTES = 0x00700000,
        ALIGN_128BYTES = 0x00800000,
        ALIGN_256BYTES = 0x00900000,
        ALIGN_512BYTES = 0x00A00000,
        ALIGN_1024BYTES = 0x00B00000,
        ALIGN_2048BYTES = 0x00C00000,
        ALIGN_4096BYTES = 0x00D00000,
        ALIGN_8192BYTES = 0x00E00000,
        ALIGN_MASK = 0x00F00000,
        LNK_NRELOC_OVFL = 0x01000000, // Section contains extended relocations.
        MEM_DISCARDABLE = 0x02000000, // Section can be discarded.
        MEM_NOT_CACHED = 0x04000000, // Section is not cachable.
        MEM_NOT_PAGED = 0x08000000, // Section is not pageable.
        MEM_SHARED = 0x10000000, // Section is shareable.
        MEM_EXECUTE = 0x20000000, // Section is executable.
        MEM_READ = 0x40000000, // Section is readable.
        MEM_WRITE = 0x80000000 // Section is writeable.
    }
    
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_DOS_HEADER
    {
        public IMAGE_DOS_SIGNATURE e_magic; // Magic number
        public ushort e_cblp; // public bytes on last page of file
        public ushort e_cp; // Pages in file
        public ushort e_crlc; // Relocations
        public ushort e_cparhdr; // Size of header in paragraphs
        public ushort e_minalloc; // Minimum extra paragraphs needed
        public ushort e_maxalloc; // Maximum extra paragraphs needed
        public ushort e_ss; // Initial (relative) SS value
        public ushort e_sp; // Initial SP value
        public ushort e_csum; // Checksum
        public ushort e_ip; // Initial IP value
        public ushort e_cs; // Initial (relative) CS value
        public ushort e_lfarlc; // File address of relocation table
        public ushort e_ovno; // Overlay number
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
        public string e_res; // This will contain 'Detours!' if patched in memory
        public ushort e_oemid; // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo; // OEM information; e_oemid specific
        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=10)] // , ArraySubType=UnmanagedType.U4
        public ushort[] e_res2; // Reserved public ushorts
        public int e_lfanew; // File address of new exe header
    }
        
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_FILE_HEADER
    {
        public IMAGE_FILE_MACHINE Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public IMAGE_FILE_CHARACTERISTICS Characteristics;
    }
        
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_NT_HEADERS32
    {
        public IMAGE_NT_SIGNATURE Signature;
        public _IMAGE_FILE_HEADER FileHeader;
        public _IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }
        
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_NT_HEADERS64
    {
        public IMAGE_NT_SIGNATURE Signature;
        public _IMAGE_FILE_HEADER FileHeader;
        public _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }
        
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_OPTIONAL_HEADER32
    {
        public IMAGE_NT_OPTIONAL_HDR_MAGIC Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public IMAGE_SUBSYSTEM Subsystem;
        public IMAGE_DLLCHARACTERISTICS DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=16)]
        public _IMAGE_DATA_DIRECTORY[] DataDirectory;
    }
        
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_OPTIONAL_HEADER64
    {
        public IMAGE_NT_OPTIONAL_HDR_MAGIC Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public IMAGE_SUBSYSTEM Subsystem;
        public IMAGE_DLLCHARACTERISTICS DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst=16)]
        public _IMAGE_DATA_DIRECTORY[] DataDirectory;
    }
        
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }
        
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions; // RVA from base of image
        public uint AddressOfNames; // RVA from base of image
        public uint AddressOfNameOrdinals; // RVA from base of image
    }
       
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public IMAGE_SCN Characteristics;
    }
        
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_IMPORT_DESCRIPTOR
    {
        public uint OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
        public uint TimeDateStamp; // 0 if not bound,
                                            // -1 if bound, and real date/time stamp
                                            // in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)
        public uint ForwarderChain; // -1 if no forwarders
        public uint Name;
        public uint FirstThunk; // RVA to IAT (if bound this IAT has actual addresses)
    }

    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_THUNK_DATA32
    {
        public Int32 AddressOfData; // PIMAGE_IMPORT_BY_NAME
    }

    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_THUNK_DATA64
    {
        public Int64 AddressOfData; // PIMAGE_IMPORT_BY_NAME
    }
        
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct _IMAGE_IMPORT_BY_NAME
    {
        public ushort Hint;
        public char Name;
    }
}
"@

$compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
$compileParams.ReferencedAssemblies.AddRange(@('System.dll', 'mscorlib.dll'))
$compileParams.GenerateInMemory = $True
Add-Type -TypeDefinition $code -CompilerParameters $compileParams -PassThru -WarningAction SilentlyContinue | Out-Null
}
function Get-DriverImports {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DllName
    )

    function Convert-RVAToFileOffset([int64]$Rva, [PSObject[]]$SectionHeaders) {
        foreach ($Section in $SectionHeaders) {
            $SecVA   = [int64][uint32]$Section.VirtualAddress
            $SecSize = [int64][uint32]$Section.VirtualSize
            $RawPtr  = [int64][uint32]$Section.PointerToRawData

            if ($Rva -ge $SecVA -and $Rva -lt ($SecVA + $SecSize)) {
                return $Rva - $SecVA + $RawPtr
            }
        }
        return $Rva
    }

    $DllPath = $DllName
    if (-not (Test-Path $DllPath)) {
        $DllPath = Join-Path -Path $env:windir -ChildPath "System32\$DllName"
    }

    if (-not (Test-Path $DllPath)) {
        Write-Error "DLL file not found at: $DllPath"
        return $null
    }

    $FileByteArray = [System.IO.File]::ReadAllBytes($DllPath)
    $Handle = [GCHandle]::Alloc($FileByteArray, 'Pinned')
    $PEBaseAddr = $Handle.AddrOfPinnedObject()

    $ImportList = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        # 1. Parse DOS Header
        $DosHeader = [Marshal]::PtrToStructure($PEBaseAddr, [Type] [PE+_IMAGE_DOS_HEADER])
        $NtHeaderLong = $PEBaseAddr.ToInt64() + $DosHeader.e_lfanew
        $PointerNtHeader = [IntPtr]$NtHeaderLong

        # 2. Detect Architecture & Select Struct
        $NtHeader32 = [Marshal]::PtrToStructure($PointerNtHeader, [Type] [PE+_IMAGE_NT_HEADERS32])
        $Architecture = $NtHeader32.FileHeader.Machine.ToString()
        
        $Is64Bit = $false
        if ($Architecture -eq 'AMD64' -or $Architecture -eq '267' -or $Architecture -eq '0x8664') {
            $NtHeaderType = [PE+_IMAGE_NT_HEADERS64]
            $Is64Bit = $true
        } elseif ($Architecture -eq 'I386' -or $Architecture -eq '332' -or $Architecture -eq '0x014c') {
            $NtHeaderType = [PE+_IMAGE_NT_HEADERS32]
        } else {
            Write-Error "Unsupported architecture: $Architecture"
            return $null
        }

        # Parse correct NT header
        $NtHeader = [Marshal]::PtrToStructure($PointerNtHeader, [Type] $NtHeaderType)
        $NumSections = $NtHeader.FileHeader.NumberOfSections

        # Explicit Section Header Calculation
        $SizeOfOptionalHeader = $NtHeader.FileHeader.SizeOfOptionalHeader
        $PointerSectionHeader = [IntPtr]($NtHeaderLong + 4 + 20 + $SizeOfOptionalHeader)

        # 3. Parse Section Headers
        $SectionHeaders = New-Object PSObject[]($NumSections)
        $SectionHeaderSize = [Marshal]::SizeOf([Type] [PE+_IMAGE_SECTION_HEADER])
        for ($i = 0; $i -lt $NumSections; $i++) {
            $SectionHeaders[$i] = [Marshal]::PtrToStructure(
                [IntPtr]($PointerSectionHeader.ToInt64() + ($i * $SectionHeaderSize)),
                [Type] [PE+_IMAGE_SECTION_HEADER]
            )
        }

        # 4. Check for Import Data Directory (Index 1)
        $ImportDirRVA = [int64][uint32]$NtHeader.OptionalHeader.DataDirectory[1].VirtualAddress
        if ($ImportDirRVA -eq 0) {
            Write-Warning "Module does not contain an Import Directory."
            return @()
        }

        $ImportDirOffset = Convert-RVAToFileOffset -Rva $ImportDirRVA -SectionHeaders $SectionHeaders
        $DescriptorSize = [Marshal]::SizeOf([Type][PE+_IMAGE_IMPORT_DESCRIPTOR])
        $CurrentImportDescriptorOffset = $ImportDirOffset

        # Loop through each dependency block (Import Descriptor)
        while ($true) {
            if ($CurrentImportDescriptorOffset -ge $FileByteArray.Length) { break }

            $DescriptorPtr = [IntPtr]($PEBaseAddr.ToInt64() + $CurrentImportDescriptorOffset)
            $ImportDescriptor = [Marshal]::PtrToStructure($DescriptorPtr, [Type][PE+_IMAGE_IMPORT_DESCRIPTOR])

            # End of Import Table marker
            if ($ImportDescriptor.Characteristics -eq 0 -and $ImportDescriptor.Name -eq 0 -and $ImportDescriptor.FirstThunk -eq 0) {
                break
            }
            if ($ImportDescriptor.Name -eq 0) { break }

            # Resolve dependent DLL name
            $NameRva = [int64][uint32]$ImportDescriptor.Name
            $ImportedDllNameOffset = Convert-RVAToFileOffset -Rva $NameRva -SectionHeaders $SectionHeaders
            $ImportedDllName = [Marshal]::PtrToStringAnsi([IntPtr]($PEBaseAddr.ToInt64() + $ImportedDllNameOffset))

            # FIX: Explicitly check OriginalFirstThunk (Characteristics). If 0, use FirstThunk.
            # This protects against reading garbage metadata strings outside the IAT.
            $ThunkRVA = [int64][uint32]$ImportDescriptor.Characteristics
            if ($ThunkRVA -eq 0) {
                $ThunkRVA = [int64][uint32]$ImportDescriptor.FirstThunk
            }

            if ($ThunkRVA -eq 0) {
                $CurrentImportDescriptorOffset += $DescriptorSize
                continue
            }

            $ThunkOffset = Convert-RVAToFileOffset -Rva $ThunkRVA -SectionHeaders $SectionHeaders
            $ThunkSize = if ($Is64Bit) { 8 } else { 4 }
            $CurrentThunkOffset = $ThunkOffset

            # Inner loop: Collect functions for this module block
            while ($true) {
                if ($CurrentThunkOffset -ge $FileByteArray.Length) { break }

                $ThunkValue = if ($Is64Bit) {
                    [Marshal]::ReadInt64([IntPtr]($PEBaseAddr.ToInt64() + $CurrentThunkOffset))
                } else {
                    [Marshal]::ReadInt32([IntPtr]($PEBaseAddr.ToInt64() + $CurrentThunkOffset))
                }

                if ($ThunkValue -eq 0) { break }

                # Check if imported by Ordinal vs Named String
                $OrdinalBitMask = if ($Is64Bit) { [Int64]::MinValue } else { [Int32]::MinValue }
                if (($ThunkValue -band $OrdinalBitMask) -eq 0) {
                    
                    $SafeRva = [int64]($ThunkValue -band 0x7FFFFFFF)
                    $NameStructOffset = Convert-RVAToFileOffset -Rva $SafeRva -SectionHeaders $SectionHeaders
                    
                    if ($NameStructOffset -lt $FileByteArray.Length) {
                        # +2 skips the structural Hint word inside the IMAGE_IMPORT_BY_NAME record
                        $ImportedFuncName = [Marshal]::PtrToStringAnsi([IntPtr]($PEBaseAddr.ToInt64() + $NameStructOffset + 2))

                        if (-not [string]::IsNullOrEmpty($ImportedFuncName)) {
                            $ImportList.Add([PSCustomObject]@{
                                ImportedFunction = $ImportedFuncName
                                SourceModule     = $ImportedDllName
                                ImportType       = "Name"
                            })
                        }
                    }
                } else {
                    $OrdinalValue = $ThunkValue -band 0xFFFF
                    $ImportList.Add([PSCustomObject]@{
                        ImportedFunction = "Ordinal_$OrdinalValue"
                        SourceModule     = $ImportedDllName
                        ImportType       = "Ordinal"
                    })
                }

                $CurrentThunkOffset += $ThunkSize
            }

            $CurrentImportDescriptorOffset += $DescriptorSize
        }

        return $ImportList

    } finally {
        if ($Handle -and $Handle.IsAllocated) {
            $Handle.Free()
        }
    }
}
function Scan-DriverPrimitive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$CustomPath,

        [Parameter(Mandatory = $false, Position = 1)]
        [switch]$System32,

        [Parameter(Mandatory = $false, Position = 2)]
        [switch]$Drivers,

        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$ProgramFiles,

        [Parameter(Mandatory = $false, Position = 4)]
        [switch]$NoRecurse,

        [Parameter(Mandatory = $false, Position = 5)]
        [switch]$IncludeAll,

        [Parameter(Mandatory = $false, Position = 6)]
        [switch]$ValidateLolDrivers,

        [Parameter(Mandatory = $false, Position = 7)]
        [switch]$ValidateMSBlockPolicy,

        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateSet('Basic', 'Extended')]
        [string]$ScanMode = 'Basic'
    )

    begin {
        # Force TLS 1.2/1.3 for secure downloads
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

        # --- SHORTER LIST (The Most Commonly Attacked Primitives + Process Termination) ---
        $BasicList = @(
            # Physical Memory Mapping (The #1 target for arbitrary read/write)
            "MmMapIoSpace", "MmMapIoSpaceEx", "ZwMapViewOfSection", "NtMapViewOfSection",
            
            # Kernel Memory Copying / Manipulation (Direct exploitation targets)
            "MmCopyVirtualMemory", "MmCopyMemory",
            
            # CPU Control & Register Tampering (Used to hijack kernel control flow / bypass KASLR)
            "__readmsr", "__writemsr", "__writecr3", "__writecr4",

            # Process Termination (Abused to forcibly kill security agents/EDRs from Ring 0)
            "ZwTerminateProcess", "NtTerminateProcess",

            #Misc
            "MmGetSystemRoutineAddress"
        )

        # --- EXTENDED LIST (Auxiliary, Allocation, and Rootkit-Style Callbacks) ---
        $ExtendedExtensions = @(
            # Memory allocation & advanced mapping variants
            "MmMapLockedPages", "MmMapLockedPagesSpecifyCache", "MmMapLockedPagesWithReservedMapping",
            "MmMapUserAddressesToPageDirectory", "MmAllocateMappingAddress", "MmFreeMappingAddress",
            "MmMapVideoDisplay", "MmUnmapVideoDisplay", "ExAllocatePool", "ExAllocatePoolWithTag", "ExAllocatePool2",
            
            # Address resolution & hardware pointer lookups
            "MmGetPhysicalAddress", "MmGetVirtualForPhysical", "MmGetPhysicalMemoryRanges",
            "MmIsAddressValid", "MmAllocatePagesForMdlEx", "ObReferenceObjectByName", "IoGetDeviceObjectPointer",
            "ObOpenObjectByPointer", "ObReferenceObjectByHandle",

            # Direct hardware port input/output
            "READ_PORT_UCHAR", "READ_PORT_USHORT", "READ_PORT_ULONG",
            "WRITE_PORT_UCHAR", "WRITE_PORT_USHORT", "WRITE_PORT_ULONG",
            "READ_PORT_BUFFER_UCHAR", "READ_PORT_BUFFER_USHORT", "READ_PORT_BUFFER_ULONG",
            "WRITE_PORT_BUFFER_UCHAR", "WRITE_PORT_BUFFER_USHORT", "WRITE_PORT_BUFFER_ULONG",

            # Remaining CPU Control Registers
            "__readcr0", "__writecr0", "__readcr2", "__writecr2", "__readcr8", "__writecr8",

            # Process/Thread Manipulation & Lookups (Excluding the core termination APIs)
            "ZwOpenProcess", "PsLookupProcessByProcessId", "ZwTerminateThread", "PsTerminateSystemThread", "PsLookupThreadByThreadId",

            # EDR / Security Callback Stripping (Rootkit/Blinding Behaviors)
            "CmUnRegisterCallback", "ObUnRegisterCallbacks", 
            "PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutineEx",
            "PsSetCreateThreadNotifyRoutine", "PsSetLoadImageNotifyRoutine"
        )

        # Build target array based on selected Mode
        $SelectedArray = switch ($ScanMode) {
            'Basic'    { $BasicList }
            'Extended' { $BasicList + $ExtendedExtensions }
        }

        # --- SCORING WEIGHTS ENGINE (10 = Worst, 1 = OK) ---
        $ScoringEngine = @{
            # Physical Memory Mapping & User Space Exposure
            "MmMapIoSpace" = 10; "MmMapIoSpaceEx" = 10; "ZwMapViewOfSection" = 10; "NtMapViewOfSection" = 10;
            "MmMapLockedPages" = 10; "MmMapLockedPagesSpecifyCache" = 10; "MmMapLockedPagesWithReservedMapping" = 10;
            "MmMapUserAddressesToPageDirectory" = 10; "MmMapVideoDisplay" = 10;

            # Process Termination & EDR Callback Disabling
            "ZwTerminateProcess" = 10; "NtTerminateProcess" = 10;
            "CmUnRegisterCallback" = 10; "ObUnRegisterCallbacks" = 10;

            # CPU Control & Register Writes (Hijacking Kernel Flow)
            "__writemsr" = 9; "__writecr3" = 9; "__writecr4" = 9; "__writecr0" = 9; "__writecr2" = 9; "__writecr8" = 9;

            # Memory Manipulation / Reading & Copying Virtual Space
            "MmCopyVirtualMemory" = 8; "MmCopyMemory" = 8;

            # Direct Hardware Port Access / Outbound Writes
            "WRITE_PORT_UCHAR" = 7; "WRITE_PORT_USHORT" = 7; "WRITE_PORT_ULONG" = 7;
            "WRITE_PORT_BUFFER_UCHAR" = 7; "WRITE_PORT_BUFFER_USHORT" = 7; "WRITE_PORT_BUFFER_ULONG" = 7;
            "READ_PORT_UCHAR" = 6; "READ_PORT_USHORT" = 6; "READ_PORT_ULONG" = 6;
            "READ_PORT_BUFFER_UCHAR" = 6; "READ_PORT_BUFFER_USHORT" = 6; "READ_PORT_BUFFER_ULONG" = 6;
            "__readmsr" = 6; "__readcr0" = 6; "__readcr2" = 6; "__readcr8" = 6;

            # Threat / Process & Thread Monitoring Manipulation
            "ZwTerminateThread" = 5; "PsTerminateSystemThread" = 5;
            "PsSetCreateProcessNotifyRoutine" = 5; "PsSetCreateProcessNotifyRoutineEx" = 5;
            "PsSetCreateThreadNotifyRoutine" = 5; "PsSetLoadImageNotifyRoutine" = 5;

            # API Resolvers & Open Handle Lookups
            "MmGetSystemRoutineAddress" = 4; "ObReferenceObjectByName" = 4; "IoGetDeviceObjectPointer" = 4;
            "ObOpenObjectByPointer" = 4; "ObReferenceObjectByHandle" = 4; "PsLookupProcessByProcessId" = 4;
            "PsLookupThreadByThreadId" = 4; "ZwOpenProcess" = 4;

            # Memory Allocation & Information Queries
            "ExAllocatePool" = 2; "ExAllocatePoolWithTag" = 2; "ExAllocatePool2" = 2;
            "MmGetPhysicalAddress" = 2; "MmGetVirtualForPhysical" = 2; "MmGetPhysicalMemoryRanges" = 2;
            "MmIsAddressValid" = 2; "MmAllocatePagesForMdlEx" = 2; "MmAllocateMappingAddress" = 2;
            "MmFreeMappingAddress" = 2; "MmUnmapVideoDisplay" = 2;
        }

        $BYOVDPrimitives = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$SelectedArray, 
            [System.StringComparer]::OrdinalIgnoreCase
        )

        # --- LOLDrivers API Integration ---
        $LolHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $LolNames  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $LolMetadata = @{}

        if ($ValidateLolDrivers) {
            Write-Host "[*] Fetching latest LOLDrivers database..." -ForegroundColor Cyan
            try {
                $RawText = Invoke-RestMethod -Uri "https://www.loldrivers.io/api/drivers.json" -ErrorAction Stop
                
                Add-Type -AssemblyName System.Web.Extensions
                $Serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                $Serializer.MaxJsonLength = 2147483647 
                
                $LolData = $Serializer.DeserializeObject($RawText)

                foreach ($Driver in $LolData) {
                    if ($Driver.ContainsKey("Tags") -and $Driver["Tags"] -is [System.Collections.IEnumerable]) {
                        foreach ($Tag in $Driver["Tags"]) {
                            if ($Tag -like "*.sys") { [void]$LolNames.Add($Tag) }
                        }
                    }
                    
                    if ($Driver.ContainsKey("KnownVulnerableSamples") -and $Driver["KnownVulnerableSamples"] -is [System.Collections.IEnumerable]) {
                        $CategoryStr = if ($Driver.ContainsKey("Category")) { $Driver["Category"] } else { "Unknown" }
                        $DescStr = "N/A"
                        if ($Driver.ContainsKey("Commands") -and $Driver["Commands"] -is [System.Collections.IDictionary]) {
                            if ($Driver["Commands"].ContainsKey("Description")) { $DescStr = $Driver["Commands"]["Description"] }
                        }
                        $DriverId = if ($Driver.ContainsKey("Id")) { $Driver["Id"] } else { "" }

                        foreach ($Sample in $Driver["KnownVulnerableSamples"]) {
                            if ($Sample -is [System.Collections.IDictionary]) {
                                if ($Sample.ContainsKey("Filename") -and $Sample["Filename"]) { 
                                    [void]$LolNames.Add($Sample["Filename"]) 
                                }
                                
                                @("SHA256", "SHA1", "MD5") | ForEach-Object {
                                    if ($Sample.ContainsKey($_) -and $Sample[$_]) {
                                        $HashStr = $Sample[$_].ToString()
                                        [void]$LolHashes.Add($HashStr)
                                        $LolMetadata[$HashStr.ToLower()] = @{
                                            Category    = $CategoryStr
                                            Description = $DescStr
                                            Id          = $DriverId
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Write-Host "[+] Successfully indexed $($LolHashes.Count) LOLDrivers signatures." -ForegroundColor Green
            } catch {
                Write-Warning "Failed to contact or parse LOLDrivers API. Error: $_"
            }
        }

        # --- Microsoft Vulnerable Driver Blocklist Integration ---
        $MSBlockedHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($ValidateMSBlockPolicy) {
            Write-Host "[*] Fetching and parsing Microsoft Vulnerable Driver Blocklist..." -ForegroundColor Cyan
            try {
                $DestinationZip = "$env:TEMP\VulnerableDriverBlockList.zip"
                $ExtractPath = "$env:TEMP\VulnerableDriverBlockList_Extracted"
        
                Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile $DestinationZip -ErrorAction Stop
        
                if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force }
                Expand-Archive -Path $DestinationZip -DestinationPath $ExtractPath -Force
        
                $XmlFile = Get-ChildItem -Path $ExtractPath -Filter "DriverPolicy_Enforced.xml" -Recurse | Select-Object -First 1
                if ($null -ne $XmlFile) {
                    [xml]$MSDoc = Get-Content -Path $XmlFile.FullName -Raw
                    foreach ($Rule in $MSDoc.SiPolicy.FileRules.Deny) {
                        if ($Rule.Hash -and $Rule.Hash.Length -eq 64 -and $Rule.FriendlyName -match 'Hash Sha256' -and $Rule.FriendlyName -notmatch 'Page') {
                            [void]$MSBlockedHashes.Add($Rule.Hash)
                        }
                    }
                    Write-Host "[+] Successfully indexed $($MSBlockedHashes.Count) standard Microsoft SHA256 signatures." -ForegroundColor Green
                } else {
                    Write-Warning "DriverPolicy_Enforced.xml was not located."
                }
        
                Remove-Item $DestinationZip -Force -ErrorAction SilentlyContinue
                Remove-Item $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Failed to dynamically download or unpack Microsoft block definitions. Error: $_"
            }
        }

        # Build target paths array
        $TargetPaths = [System.Collections.Generic.List[string]]::new()
        if ($System32)     { $TargetPaths.Add("$env:SystemRoot\System32") }
        if ($Drivers)      { $TargetPaths.Add("$env:SystemRoot\System32\drivers") }
        if ($ProgramFiles) { $TargetPaths.Add($env:ProgramFiles); $TargetPaths.Add(${env:ProgramFiles(x86)}) }
        if ($CustomPath)   { $TargetPaths.Add($CustomPath) }

        if ($TargetPaths.Count -eq 0) {
            $TargetPaths.Add("$env:SystemRoot\System32")
            $TargetPaths.Add("$env:SystemRoot\System32\drivers")
            $TargetPaths.Add($env:ProgramFiles)
            $TargetPaths.Add(${env:ProgramFiles(x86)})
        }
    }

    process {
        $TargetPaths | Select-Object -Unique | ForEach-Object {
            $CurrentFolder = $_
            if (-not (Test-Path -Path $CurrentFolder)) { return }

            $GCIParams = @{
                Path        = $CurrentFolder
                Filter      = "*.sys"
                ErrorAction = "SilentlyContinue"
            }
            if (-not $NoRecurse) { $GCIParams.Recurse = $true }

            Get-ChildItem @GCIParams | ForEach-Object {
                $File = $_
                try {
                    $Imports = Get-DriverImports -DllName $File.FullName -ErrorAction SilentlyContinue
                    if ($null -eq $Imports) { return }

                    # Track findings and calculate high score dynamically
                    $CalculatedScore = 1
                    $FoundPrimitives = foreach ($Match in $Imports) {
                        if ($BYOVDPrimitives.Contains($Match.ImportedFunction)) {
                            # Fetch internal primitive evaluation score
                            $MatchScore = 1
                            if ($ScoringEngine.ContainsKey($Match.ImportedFunction)) {
                                $MatchScore = $ScoringEngine[$Match.ImportedFunction]
                            }
                            if ($MatchScore -gt $CalculatedScore) { $CalculatedScore = $MatchScore }

                            "[from $($Match.SourceModule)] -> $($Match.ImportedFunction) (Threat: $MatchScore)"
                        }
                    }

                    # Calculate Hash early to check both verification paths
                    $HashSHA256 = "UNKNOWN"
                    $IsLolMatch = $false
                    $IsMSMatch  = $false
                    $LolMatchDetails = $null

                    try {
                        $HashSHA256 = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                        
                        # Validate Against LOLDrivers
                        if ($ValidateLolDrivers -and $LolHashes.Contains($HashSHA256)) {
                            $IsLolMatch = $true
                            $LolMatchDetails = $LolMetadata[$HashSHA256.ToLower()]
                        }

                        # Validate Against Microsoft Blocklist
                        if ($ValidateMSBlockPolicy -and $MSBlockedHashes.Contains($HashSHA256)) {
                            $IsMSMatch = $true
                        }
                    } catch {
                        $HashSHA256 = "LOCKED / ACCESS DENIED"
                    }

                    # Fallback lookup match by name for LOLDrivers
                    if ($ValidateLolDrivers -and -not $IsLolMatch -and $LolNames.Contains($File.Name)) {
                        $IsLolMatch = $true
                    }

                    # Dynamic database verification automatically overrides score to 10
                    if ($IsLolMatch -or $IsMSMatch) { $CalculatedScore = 10 }

                    # Output evaluation criteria matches
                    if ($FoundPrimitives -or $IsLolMatch -or $IsMSMatch) {
                        $VersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
                        $CompanyName = $VersionInfo.CompanyName

                        # Filtering engine configuration parameters
                        if (-not $IncludeAll -and -not $IsLolMatch -and -not $IsMSMatch) {
                            if ([string]::IsNullOrWhiteSpace($CompanyName) -or $CompanyName -match "Microsoft") {
                                return
                            }
                        }

                        Write-Host "--------------------------------------------------" -ForegroundColor Gray
                        
                        if ($IsLolMatch) {
                            Write-Host "[!!!] MATCHED LOLDRIVERS DATABASE [!!!]" -ForegroundColor Magenta
                            if ($LolMatchDetails) {
                                Write-Host "CATEGORY:  $($LolMatchDetails.Category.ToUpper())" -ForegroundColor Green
                                Write-Host "DETAILS:   $($LolMatchDetails.Description)" -ForegroundColor Green
                            }
                        }

                        if ($IsMSMatch) {
                            Write-Host "[!!!] MATCHED OFFICIAL MICROSOFT DRIVER BLOCKLIST [!!!]" -ForegroundColor Black -BackgroundColor DarkYellow
                        }

                        # Apply dynamic alert color based on severity score
                        $UiColor = "Green"
                        if ($CalculatedScore -ge 8) { $UiColor = "Red" }
                        elseif ($CalculatedScore -ge 5) { $UiColor = "Yellow" }
                        elseif ($CalculatedScore -gt 1) { $UiColor = "Cyan" }

                        Write-Host "THREAT SCORE: [$CalculatedScore / 10]" -ForegroundColor $UiColor -BackgroundColor Black
                        Write-Host "SCAN MODE:    [$ScanMode]" -ForegroundColor DarkCyan
                        Write-Host "PATH:         $($File.FullName)" -ForegroundColor Cyan
                        Write-Host "DRIVER:       $($File.Name)"
                        Write-Host "COMPANY:      $      ($CompanyName)"
                        Write-Host "INFO:         $($VersionInfo.FileDescription)"
                        Write-Host "SHA256:       $HashSHA256" -ForegroundColor DarkGray
                        
                        if ($FoundPrimitives) {
                            Write-Host "SUSPICIOUS IMPORTS:" -ForegroundColor Yellow
                            foreach ($Primitive in $FoundPrimitives) {
                                Write-Host "  --> $Primitive" -ForegroundColor Yellow
                            }
                        } else {
                            Write-Host "IMPORTS: No target primitives matched, but found inside validation databases." -ForegroundColor Gray
                        }
                    }
                } catch {
                    return
                }
            }

        }
    }
}