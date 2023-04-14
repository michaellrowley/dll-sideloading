#include <iostream>
#include <chrono>
#include <vector>
#include <thread>
#include <string>
#include <functional>
#include <Windows.h>
#include <TlHelp32.h>

class CleanupObj {
    const std::function<void()> CleanupFn;
    bool Toggle = true;
public:
    void DisableCleanup() { this->Toggle = false; }
    CleanupObj(const std::function<void()>& CleanupFunction) : CleanupFn(CleanupFunction), Toggle(true) { }
    ~CleanupObj() {
        if (this->Toggle) {
            this->CleanupFn();
        }
    }
};

bool InjectDLL(const HANDLE ProcessHandle, const std::wstring& DLLPath) {
    static const FARPROC LoadLibAddress = GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "LoadLibraryW");
    LPVOID RemotePathAddress = 0x00000000;

    CleanupObj Cleaner([&RemotePathAddress, ProcessHandle, DLLPath]() {
        const LPVOID FreeAddr = RemotePathAddress;
        const std::size_t DLLPathSize = DLLPath.size() * sizeof(wchar_t);
        if (FreeAddr != 0x00000000) {
            std::thread([FreeAddr, ProcessHandle, DLLPathSize]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                if (!VirtualFreeEx(ProcessHandle, FreeAddr, DLLPathSize, MEM_DECOMMIT)) {
                    std::cerr << "[!] Unable to free DLL path in process memory\n";
                }
            }).detach();
        }
    });

    RemotePathAddress = VirtualAllocEx(ProcessHandle, NULL, DLLPath.length() * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (RemotePathAddress == 0x00000000) {
        std::cerr << "[!] Unable to allocate memory in process memory\n";
        return false;
    }
    SIZE_T RemotePathBytesWritten;
    if (!WriteProcessMemory(ProcessHandle, RemotePathAddress, DLLPath.c_str(), DLLPath.length() * sizeof(wchar_t), &RemotePathBytesWritten) ||
        RemotePathBytesWritten == 0) {
        std::cerr << "[!] Unable to write DLL path to process memory\n";
        return false;
    }

    DWORD LoadLibraryThreadId = 0;
    // Generalising GetProcAddress and GetModuleHandleA from *this* process towards another one is a pretty strange leap to me but it seems to work since KERNEL32 is one of the first
    // libraries loaded and thus will almost always be based into the same relative *virtual* address.
    if (CreateRemoteThread(ProcessHandle, NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibAddress), RemotePathAddress, NULL, &LoadLibraryThreadId) == NULL ||
        LoadLibraryThreadId == 0) {
        std::cerr << "[!] Unable to spawn thread in process\n";
        return false;
    }

    return true;
}

void TraverseAndInject(const HANDLE ProcHandle, const DWORD PID, std::vector<HANDLE>& ChildProcesses, LPVOID& RemotePathAddress, const std::wstring& DLLPath) {
    // Hooking all of the ways that a new process could be spawned isn't going to work as there are just soo many functions and they don't
    // all wrap around a single export.
    PROCESSENTRY32W IterativeProcess = { 0 };
    IterativeProcess.dwSize = sizeof(PROCESSENTRY32W);
    //DWORD ExitCode = STILL_ACTIVE;
    while (true/*GetExitCodeProcess(ProcHandle, &ExitCode) && ExitCode == STILL_ACTIVE*/) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Can't afford a huge delay between launch and discovery.
        const HANDLE SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, PID);
        if (!SnapshotHandle) {
            return;
        }
        if (!Process32FirstW(SnapshotHandle, &IterativeProcess)) {
            return;
        }
        do {
            static std::vector<DWORD> ProcessedChildPIDs;
            if (IterativeProcess.th32ParentProcessID == PID &&
                std::find(ProcessedChildPIDs.cbegin(), ProcessedChildPIDs.cend(), IterativeProcess.th32ProcessID) == ProcessedChildPIDs.cend()) {

                std::wcout << L"CreateProcess:"
                    L"\n\tszExeFile='" + std::wstring(IterativeProcess.szExeFile) + "'"
                    L"\n";

                ProcessedChildPIDs.push_back(IterativeProcess.th32ProcessID);

                const HANDLE ChildProcHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
                    false, IterativeProcess.th32ProcessID);
                if (ChildProcHandle == NULL) {
                    std::cerr << "[!] Unable to open handle to new child process (pid: " + std::to_string(IterativeProcess.th32ProcessID) + ")\n";
                }
                else {
                    std::cout << "[*] Opened handle to new process (pid: " + std::to_string(IterativeProcess.th32ProcessID) + ", handle: 0x" + std::format("{:08X}", reinterpret_cast<DWORD>(ChildProcHandle)) + ")\n";

                    ChildProcesses.push_back(ChildProcHandle);

                    if (InjectDLL(ChildProcHandle, DLLPath)) {
                        std::cout << "[*] Successfully injected into child process\n";
                    }
                    else {
                        std::cerr << "[!] GLE: 0x" + std::format("{:08X}", GetLastError()) + "\n";
                    }

                    std::thread(&TraverseAndInject, ChildProcHandle, IterativeProcess.th32ProcessID, std::ref(ChildProcesses), std::ref(RemotePathAddress), std::ref(DLLPath)).detach();
                }
            }
        } while (Process32NextW(SnapshotHandle, &IterativeProcess));
    }
}

int main()
{
    std::vector<HANDLE> ChildProcesses;
    PROCESS_INFORMATION ProcessInformation = {};
    LPVOID RemotePathAddress = 0x00000000;
    SIZE_T RemotePathSize = 0;
    CleanupObj ScopeBasedCleanup(std::function<void()>([&ChildProcesses, &ProcessInformation, &RemotePathAddress, &RemotePathSize]() {
        const HANDLE ProcessHandle = ProcessInformation.hProcess;

        std::cout << "[*] GetLastError(): " << std::hex << GetLastError() << std::endl;

        if (ProcessHandle != 0x0000000) {
            // Not much use in freeing memory when we're about to close the process but some termination-oriented functions
            // might need the extra memory.
            if (RemotePathAddress != 0x00000000 && RemotePathSize != 0) {
                if (!VirtualFreeEx(ProcessHandle, RemotePathAddress, RemotePathSize, MEM_DECOMMIT)) {
                    std::cerr << "[!] Unable to free DLL path from remote-process memory\n";
                }
            }
            // We don't bother freeing the LoadLibraryA thread as it should only be active for milliseconds and would be
            // killed with the process anyhow.
            if (!TerminateProcess(ProcessHandle, ERROR_TIMEOUT)) {
                std::cerr << "[!] Unable to terminate remote-process with handle '" + std::format("{:08X}", reinterpret_cast<DWORD>(ProcessHandle)) + "'\n";
            }
            for (HANDLE& ChildProcess : ChildProcesses) {
                if (!TerminateProcess(ChildProcess, ERROR_TIMEOUT)) {
                    std::cerr << "[!] Unable to terminate child of remote-process with handle '" + std::format("{:08X}", reinterpret_cast<DWORD>(ChildProcess)) + "'\n";
                }
            }
        }

        std::cout << "[*] Cleanup completed" << std::endl;
    }));
    std::cout << "[?] Executable path: ";
    std::wstring ProcessPath;
    std::getline(std::wcin, ProcessPath);

    std::cout << "\n[?] DLL to inject: ";
    std::wstring DLLPath;
    std::getline(std::wcin, DLLPath);

    std::cout << "\n[?] Directory context (empty for NULL): ";
    std::wstring CurDir;
    std::getline(std::wcin, CurDir);

    STARTUPINFOW StartupInformation = {};
    if (!CreateProcessW(ProcessPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, CurDir.empty() ? NULL : CurDir.c_str(), &StartupInformation, &ProcessInformation)) {
        std::cerr << "\n[!] Unable to spawn suspended proess" << (GetLastError() == ERROR_ELEVATION_REQUIRED ? ", insufficient elevation" : "") << std::endl;
        return 0;
    }

    std::cout << "\n[*] Spawned suspended process:\n\tProcess ID: " << ProcessInformation.dwProcessId << "\n\tThread ID: " << ProcessInformation.dwThreadId << "\n\tProcess Handle: " << std::hex << ProcessInformation.hProcess << std::endl;

    if (!InjectDLL(ProcessInformation.hProcess, DLLPath)) {
        return 0;
    }

    std::cout << "[*] Loaded DLL in remote-process memory, press enter to unsuspend";
    std::string x;
    std::getline(std::cin, x);

    if (ResumeThread(ProcessInformation.hThread) == -1) {
        std::cerr << "[!] Unable to resume thread in remote-process" << std::endl;
        return 0;
    }
    std::cout << "\n[*] Unsuspended process, press enter to terminate and exit" << std::endl;

    std::thread(&TraverseAndInject, ProcessInformation.hProcess, ProcessInformation.dwProcessId, std::ref(ChildProcesses), std::ref(RemotePathAddress), std::ref(DLLPath)).detach();
    std::getline(std::cin, x);
    return 1;
}