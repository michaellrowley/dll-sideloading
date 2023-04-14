# DLL-Sideloading
This project supports efforts to discover DLL sideloading (also known as 'DLL hijacking' or [T1574.001](https://attack.mitre.org/techniques/T1574/001/)/[T1574.002](https://attack.mitre.org/techniques/T1574/002/)) vulnerabilities where source code is unavailable and tools like [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) aren't suitable.

## Overview:
The repository currently contains two main components: a DLL that is injected into a process, and an executable that is responsible for launching and subsequently injecting into that process.

### DLL:
The DLL component modifies the import address table of whatever program it lands in to point to some of its own functions.
These 'hook callbacks' will log information to a file (composed of a hardcoded path alongside the PID of the process) which can then be reviewed to determine whether there is any interest in further review, which would typically involve reversing the binary, however the information provided in these logs could even lead straight to the 'drop a dummy DLL' stage.

### Launcher Application:
The 'launcher' component simply serves to get the DLL into as many **relevant** processes as possible, as quickly as possible.
This is accomplished by firstly spawning a suspended instance of the main application and then by creating an unsuspended thread within that application to load the DLL with.
This launcher monitors the initial application for any forks that occur and attempts to inject the DLL into new processes whilst monitoring them for more child processes.

## Usage/Example:
When running the launcher, a set of prompts appear to request some paths:
```
[?] Executable path: Z:\\...\x64\x64dbg.exe

[?] DLL to inject: Y:\\...\Preliminary-DLL.dll

[?] Directory context (empty for NULL): Z:\\...\x64\

[*] Spawned suspended process:
        Process ID: ...
        Thread ID: ...
        Process Handle: 0000000000000CC0
[*] Loaded DLL in remote-process memory, press enter to unsuspend

[*] Unsuspended process, press enter to terminate and exit
```
> Anything marked with a **[?]** requires user input, a **[*]** refers to information that you might find useful, and a **[!]** refers to an error that might require further review to diagnose/remediate.

> When testing has concluded, press enter to exit the application so that all of the injected processes can be terminated promptly.

The output format is as follows:
```C++
INITIALIZED(Base='0x...', State='NON-ADMIN', Path='Z:\\...\x64\x64dbg.exe')
HOOKED(Library='KERNEL32.dll', Function='GetProcAddress', Address='...')
HOOKED(Library='KERNEL32.dll', Function='LoadLibraryA', Address='...')
HOOKED(Library='KERNEL32.dll', Function='CreateFileW', Address='...')
LoadLibrary(Filename='dbghelp.dll', Path='Z:\\...\x64\dbghelp.dll', SDDL='O:S-1-5-21-1004336348-1177238915-682003330-512D:AI(A;ID;0x1301bf;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;S-1-5-21-1004336348-1177238915-682003330-512)')
GetProcAddress(Library='dbghelp.dll', Function='MiniDumpWriteDump')
GetProcAddress(Library='UNKNOWN', Function='SetProcessUserModeExceptionPolicy')
GetProcAddress(Library='UNKNOWN', Function='GetProcessUserModeExceptionPolicy')
```
I'd recommend splitting this into some manageable chunks based on log trigger (``LoadLibrary`` is the first sign of an issue in most cases) and then looking at each of the paths being loaded whilst filtering out any that don't fit a criteria (i.e, if you're looking to elevate privileges, ignore paths that are privileged like ``C:\\Windows``). The **SDDL** argument can help with noise data as it provides a full [security descriptor string](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format) that can provide a little more information about how accessible a given library is (which user groups can access/read/write to the location).

In the above example, the security descriptor expands to:
```JSON
...
"dacl": { ...
    "flags": "SDDL_AUTO_INHERITED",
    "ace_segments": [ ...
        { ...
            "ace_type": "SDDL_ACCESS_ALLOWED",
            "rights": [ "SDDL_FILE_ALL" ],
            "account_sid": "S-1-5-21-1004336348-1177238915-682003330-512"
        }
    ]
}
```
Meaning that the user-account with the security identifier of ``S-1-5-21-1004336348-1177238915-682003330-512`` can do anything to ``dbghelp.dll`` (hence ``SDDL_FILE_ALL`` defined in [``Sddl.h``](https://learn.microsoft.com/en-us/windows/win32/api/sddl/)).

On my system, that SID (replaced with one from MSAPI docs in this example) refers to the user account that installed x64dbg; so even if that account doesn't have administrative permissions and x64 is run, a malicious DLL dropped at ``Z:\\`` *could* be loaded into a signed application that might even be whitelisted by enough antiviruses to make it a [viable target](https://www.theregister.com/2023/03/01/plugx_dll_loading_malware/) for malicious actors. By default, x64dbg isn't run as an administrator but for certain features including kernel debugging, it is advised/required that the executable be run as an administrator - meaning that the DLL could be loaded as an administrator in these cases.

## Warning(s)
This software comes with no warranty as to its suitbility for any purpose. However, using this on a non-virtualized system or in an attempt to get a 'dynamic persistence' effect (by injecting into a variety of running processes to gather a list of dynamic-loaded DLLs before dropping in some of the flagged locations) is advised against because:

1. DLL Injection from the loader works by launching a new thread, allocating memory in another process, and indirectly triggering a kernel callback via [LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw) which calls - among others - [PsSetLoadImageNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine) which is registered by just about every security product in kernel-mode. Each of these **can easily be detected by security products**.
2. The source code **hasn't been inspected for security vulnerabilities** and could lead to additional issues arising (hence, try to run this in an isolated environment).
3. Both **components need to be compiled for the architecture of the process being tested** (it *should* be possible to get the launcher to work with some effort as the only reason that this part fails to work is due to the resolution of the ``Kernel32.dll::LoadLibraryW`` address and ASLR makes hardcoding infeasible - enumerating over modules to find ``Kernel32.dll`` and then using a hardcoded/resolved offset to find ``LoadLibraryW`` should be possible, though).
4. Pretty much every aspect of this project introduces undefined behaviour in the host process, meaning that **it could crash at any moment**.

TL;DR: This is only suitable for black-box testing in an (ideally) isolated environment.

## Compilation
Both components were developed for Windows systems and were compiled using cl.exe and the C++20 standard library. There shouldn't be any additional modifications necessary to have either source code compile.