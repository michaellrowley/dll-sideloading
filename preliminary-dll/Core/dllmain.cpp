#include <Windows.h>
#include <Shlobj.h>
#include <tlhelp32.h>

#include "../Hooking/IAT.hpp"
#include "../Hooking/Interception.hpp"
#include "./Core.hpp"

#include <chrono>
#include <thread>
#include <string>
#include <iostream>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved ) {
    if (ul_reason_for_call != DLL_PROCESS_ATTACH) {
        return TRUE;
    }
    const DWORD LocalPID = GetCurrentProcessId();

    WCHAR ExecutablePath[MAX_PATH + 1] = { 0 };
    GetModuleFileNameW(NULL, ExecutablePath, MAX_PATH); // If this function fails, ExecutablePath's first byte is zero (terminating).

    Core::Logging::Log(Core::Logging::LogType::INITIAL_LOAD,
        L"Base='0x" + std::format(L"{:08X}", reinterpret_cast<DWORD>(hModule)) + L"'"
        L", State='" + (IsUserAnAdmin() ? L"ADMINISTRATOR" : L"NON-ADMIN") + L"'"
        L", Path='" + std::wstring(ExecutablePath) + L"'");

    Hooking::IAT::LibraryHookInfo KernelHookInfo {
        .LibraryName = "KERNEL32.dll",
        .Functions {
            {std::string("LoadLibraryExA"), static_cast<PVOID>(&Hooking::Interception::LoadLibraryExA_Hook)},
            {std::string("LoadLibraryA"), static_cast<PVOID>(&Hooking::Interception::LoadLibraryA_Hook)},
            {std::string("LoadLibraryExW"), static_cast<PVOID>(&Hooking::Interception::LoadLibraryExW_Hook)},
            {std::string("LoadLibraryW"), static_cast<PVOID>(&Hooking::Interception::LoadLibraryW_Hook)},
            {std::string("GetProcAddress"), static_cast<PVOID>(&Hooking::Interception::GetProcAddress_Hook)},
            {std::string("FreeLibrary"), static_cast<PVOID>(&Hooking::Interception::FreeLibrary_Hook)},
            {std::string("OpenFile"), static_cast<PVOID>(&Hooking::Interception::OpenFile_Hook)},
            {std::string("CreateFileA"), static_cast<PVOID>(&Hooking::Interception::CreateFileA_Hook)},
            {std::string("CreateFileW"), static_cast<PVOID>(&Hooking::Interception::CreateFileW_Hook)}
        }
    };

    Hooking::IAT::HookImports(std::vector<Hooking::IAT::LibraryHookInfo>{KernelHookInfo});
    return TRUE;
}

