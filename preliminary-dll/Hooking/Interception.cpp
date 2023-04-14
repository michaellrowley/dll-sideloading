#include "Interception.hpp"
#include "../Core/Core.hpp"

#include <Windows.h>
#include <sddl.h>

#include <iostream>
#include <codecvt>
#include <locale>
#include <format>
#include <mutex>

static std::map<std::string, PVOID> CallbacksMap;
static std::mutex CallbacksMutex;

void Hooking::Interception::SetCallbackOrigin(std::string FunctionName, PVOID OriginalAddress)
{
	CallbacksMap[FunctionName] = OriginalAddress;
}

static std::map<HMODULE, std::wstring> LibraryNameMap;
static std::mutex LibraryNameMutex;

HMODULE __stdcall Hooking::Interception::LoadLibraryExA_Hook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	const HMODULE OriginalReturnValue = static_cast<HMODULE(*__stdcall)(LPCSTR, HANDLE, DWORD)>(CallbacksMap["LoadLibraryExA"])(lpLibFileName, hFile, dwFlags);
	std::cout << "LoadLibraryExA:"
		"\n\tlpLibFileName='" + std::string(lpLibFileName) + "'"
		"\n\tdwFlags=" + std::format("{:08X}", dwFlags) +
		"\n\tlpRetVal=" + std::format("{:08X}", reinterpret_cast<DWORD>(OriginalReturnValue)) +
		"\n";

	const std::string LibraryFileName(lpLibFileName);
	const std::wstring WideLibFileName(LibraryFileName.cbegin(), LibraryFileName.cend());
	std::unique_lock LibNameLock(LibraryNameMutex);
	LibraryNameMap[OriginalReturnValue] = WideLibFileName;
	LibNameLock.unlock();

	std::unique_lock CallbacksLock(CallbacksMutex);
	WCHAR FullDLLPath[MAX_PATH + 1] = { 0x00 };
	const DWORD DLLPathSize = GetModuleFileNameW(OriginalReturnValue, FullDLLPath, MAX_PATH);
	CallbacksLock.unlock();
	std::wstring DLLPath = L"RESOLUTION_FAILED";
	if (DLLPathSize != 0) {
		DLLPath = std::wstring(FullDLLPath, DLLPathSize);
	}

	const std::wstring InfoStr = L"Filename='" + WideLibFileName + L"', Path='" + DLLPath + L"', SDDL='" + Core::Utils::GetSecurityDescriptorString(DLLPath) + L"'";

	Core::Logging::Log(Core::Logging::LogType::LIBRARY_LOAD, InfoStr);

	return OriginalReturnValue;
}

HMODULE __stdcall Hooking::Interception::LoadLibraryA_Hook(LPCSTR lpLibFileName)
{
	const HMODULE OriginalReturnValue = static_cast<HMODULE(*__stdcall)(LPCSTR)>(CallbacksMap["LoadLibraryA"])(lpLibFileName);
	std::cout << "LoadLibraryA:"
		"\n\tlpLibFileName='" + std::string(lpLibFileName) + "'"
		"\n\tlpRetVal=" + std::format("{:08X}", reinterpret_cast<DWORD>(OriginalReturnValue)) +
		"\n";

	std::string LibraryFileName(lpLibFileName);
	const std::wstring WideLibFileName(LibraryFileName.cbegin(), LibraryFileName.cend());

	std::unique_lock LibNameLock(LibraryNameMutex);
	LibraryNameMap[OriginalReturnValue] = WideLibFileName;
	LibNameLock.unlock();

	std::unique_lock CallbacksLock(CallbacksMutex);
	WCHAR FullDLLPath[MAX_PATH] = {};
	const DWORD DLLPathSize = GetModuleFileNameW(OriginalReturnValue, FullDLLPath, MAX_PATH);
	CallbacksLock.unlock();
	std::wstring DLLPath = L"RESOLUTION_FAILED";
	if (DLLPathSize != 0) {
		DLLPath = std::wstring(FullDLLPath, DLLPathSize);
	}

	const std::wstring InfoStr = L"Filename='" + WideLibFileName + L"', Path='" + DLLPath + L"', SDDL='" + Core::Utils::GetSecurityDescriptorString(DLLPath) + L"'";
	Core::Logging::Log(Core::Logging::LogType::LIBRARY_LOAD, InfoStr);

	return OriginalReturnValue;
}

HMODULE __stdcall Hooking::Interception::LoadLibraryExW_Hook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	const HMODULE OriginalReturnValue = static_cast<HMODULE(*__stdcall)(LPCWSTR, HANDLE, DWORD)>(CallbacksMap["LoadLibraryExW"])(lpLibFileName, hFile, dwFlags);
	std::wcout << L"LoadLibraryExW:"
		L"\n\tlpLibFileName = '" + std::wstring(lpLibFileName) + L"'"
		"\n\tdwFlags=" + std::format(L"{:08X}", dwFlags) +
		L"\n\tlpRetVal=" + std::format(L"{:08X}", reinterpret_cast<DWORD>(OriginalReturnValue)) +
		L"\n";

	std::unique_lock LibNameLock(LibraryNameMutex);
	LibraryNameMap[OriginalReturnValue] = std::wstring(lpLibFileName);
	LibNameLock.unlock();

	std::unique_lock CallbacksLock(CallbacksMutex);
	WCHAR FullDLLPath[MAX_PATH] = {};
	const DWORD DLLPathSize = GetModuleFileNameW(OriginalReturnValue, FullDLLPath, MAX_PATH);
	CallbacksLock.unlock();
	std::wstring DLLPath = L"RESOLUTION_FAILED";
	if (DLLPathSize != 0) {
		DLLPath = std::wstring(FullDLLPath, DLLPathSize);
	}

	const std::wstring InfoStr = L"Filename='" + std::wstring(lpLibFileName) + L"', Path='" + DLLPath + L"', SDDL='" + Core::Utils::GetSecurityDescriptorString(DLLPath) + L"'";
	Core::Logging::Log(Core::Logging::LogType::LIBRARY_LOAD, InfoStr);

	return OriginalReturnValue;
}

HMODULE __stdcall Hooking::Interception::LoadLibraryW_Hook(LPCWSTR lpLibFileName)
{
	const HMODULE OriginalReturnValue = static_cast<HMODULE(*__stdcall)(LPCWSTR)>(CallbacksMap["LoadLibraryW"])(lpLibFileName);
	std::wcout << L"LoadLibraryW:"
		L"\n\tlpLibFileName='" + std::wstring(lpLibFileName) + L"'"
		L"\n\tlpRetVal=" + std::format(L"{:08X}", reinterpret_cast<DWORD>(OriginalReturnValue)) +
		L"\n";
	
	std::unique_lock LibNameLock(LibraryNameMutex);
	LibraryNameMap[OriginalReturnValue] = std::wstring(lpLibFileName);
	LibNameLock.unlock();

	std::unique_lock CallbacksLock(CallbacksMutex);
	WCHAR FullDLLPath[MAX_PATH] = {};
	const DWORD DLLPathSize = GetModuleFileNameW(OriginalReturnValue, FullDLLPath, MAX_PATH);
	CallbacksLock.unlock();
	std::wstring DLLPath = L"RESOLUTION_FAILED";
	if (DLLPathSize != 0) {
		DLLPath = std::wstring(FullDLLPath, DLLPathSize);
	}

	const std::wstring InfoStr = L"Filename='" + std::wstring(lpLibFileName) + L"', Path='" + DLLPath + L"', SDDL='" + Core::Utils::GetSecurityDescriptorString(DLLPath) + L"'";
	Core::Logging::Log(Core::Logging::LogType::LIBRARY_LOAD, InfoStr);

	return OriginalReturnValue;
}

FARPROC __stdcall Hooking::Interception::GetProcAddress_Hook(HMODULE hModule, LPCSTR lpProcName)
{
	const FARPROC OriginalReturnValue = static_cast<FARPROC(*__stdcall)(HMODULE, LPCSTR)>(CallbacksMap["GetProcAddress"])(hModule, lpProcName);

	std::unique_lock LibNameLock(LibraryNameMutex);
	const std::map<HMODULE, std::wstring>::const_iterator OriginLibrary = LibraryNameMap.find(hModule);
	const std::wstring OriginLibraryName = (OriginLibrary == LibraryNameMap.cend() ? L"UNKNOWN" : OriginLibrary->second);
	LibNameLock.unlock();
	const std::string FunctionName = std::string(lpProcName);
	const std::wstring WideFunctionName = std::wstring(FunctionName.cbegin(), FunctionName.cend());
	std::wcout << L"GetProcAddress:"
		L"\n\tlpProcName='" + WideFunctionName + "'"
		L"\n\tlpLibName='" + OriginLibraryName + L"'"
		L"\n\thModule=" + std::format(L"{:08X}", reinterpret_cast<DWORD>(hModule)) +
		L"\n\tlpRetVal=" + std::format(L"{:08X}", reinterpret_cast<DWORD>(OriginalReturnValue)) +
		L"\n";

	const std::wstring CombinedInteraction = L"Library='" + OriginLibraryName + L"', Function='" + WideFunctionName + L"'";

	Core::Logging::Log(Core::Logging::LogType::FUNCTION_LOAD, CombinedInteraction);

	return OriginalReturnValue;
}

BOOL __stdcall Hooking::Interception::FreeLibrary_Hook(HMODULE hLibModule)
{
	const BOOL OriginalReturnValue = static_cast<BOOL(*__stdcall)(HMODULE)>(CallbacksMap["FreeLibrary"])(hLibModule);

	std::unique_lock LibNameLock(LibraryNameMutex);
	const std::map<HMODULE, std::wstring>::const_iterator OriginLibrary = LibraryNameMap.find(hLibModule);

	const std::wstring OriginLibraryStr = L"Library='" + (OriginLibrary == LibraryNameMap.cend() ? L"UNKNOWN" : OriginLibrary->second) + L"'";

	std::wcout << L"FreeLibrary:"
		L"\n\thLibModule=" + std::format(L"{:08X}", reinterpret_cast<DWORD>(hLibModule)) +
		L"\n\tlpLibName='" + OriginLibraryStr +
		L"\n";

	LibraryNameMap.erase(hLibModule);
	LibNameLock.unlock();

	Core::Logging::Log(Core::Logging::LogType::LIBRARY_UNLOAD, OriginLibraryStr);

	return OriginalReturnValue;
}

HFILE __stdcall Hooking::Interception::OpenFile_Hook(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle) {
	const HFILE OriginalReturnValue = static_cast<HFILE(*__stdcall)(LPCSTR, LPOFSTRUCT, UINT)>(CallbacksMap["OpenFile"])(lpFileName, lpReOpenBuff, uStyle);

	const std::string FileNameStr(lpFileName);
	std::cout << "OpenFile:"
		"\n\tlpFileName='" + FileNameStr + "'"
		"\n\tlpReOpenBuff->szPathName='" + std::string(lpReOpenBuff->szPathName) + "'"
		"\n\tuStyle=" + std::format("{:08X}", uStyle) +
		"\n";

	const std::wstring FileNameWstr(FileNameStr.cbegin(), FileNameStr.cend());

	Core::Logging::Log(Core::Logging::LogType::FILE_LOAD,
		FileNameWstr + L"/" +
		std::format(L"{:08X}", uStyle) + L"/" +
		std::format(L"{:08X}", lpReOpenBuff->nErrCode) + L"/" +
		Core::Utils::GetSecurityDescriptorString(FileNameWstr));

	return OriginalReturnValue;
}

HANDLE __stdcall Hooking::Interception::CreateFileA_Hook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	const HANDLE OriginalReturnValue = static_cast<HANDLE(*__stdcall)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)>(CallbacksMap["CreateFileA"])(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	const std::string FileNameStr(lpFileName);
	std::cout << "CreateFileA:"
		"\n\tlpFileName='" + FileNameStr + "'"
		"\n\tdwDesiredAccess=" + std::format("{:08X}", dwDesiredAccess) +
		"\n\tdwCreationDisposition=" + std::format("{:08X}", dwCreationDisposition) +
		"\n\tdwFlagsAndAttributes=" + std::format("{:08X}", dwFlagsAndAttributes) +
		"\n";

	const std::wstring FileNameWstr(FileNameStr.cbegin(), FileNameStr.cend());
	Core::Logging::Log(Core::Logging::LogType::CREATE_FILE, FileNameWstr + L"/" +
		std::format(L"{:08X}", dwDesiredAccess) + L"/" +
		std::format(L"{:08X}", dwCreationDisposition) + L"/" +
		std::format(L"{:08X}", dwFlagsAndAttributes) + L"/" +
		Core::Utils::GetSecurityDescriptorString(FileNameWstr));

	return OriginalReturnValue;
}

HANDLE __stdcall Hooking::Interception::CreateFileW_Hook(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	const HANDLE OriginalReturnValue = static_cast<HANDLE(*__stdcall)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)>(CallbacksMap["CreateFileW"])(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	const std::wstring FileNameStr(lpFileName);
	std::wcout << L"CreateFileA:"
		L"\n\tlpFileName='" + FileNameStr + L"'"
		L"\n\tdwDesiredAccess=" + std::format(L"{:08X}", dwDesiredAccess) +
		L"\n\tdwCreationDisposition=" + std::format(L"{:08X}", dwCreationDisposition) +
		L"\n\tdwFlagsAndAttributes=" + std::format(L"{:08X}", dwFlagsAndAttributes) +
		L"\n";

	Core::Logging::Log(Core::Logging::LogType::CREATE_FILE, FileNameStr + L"/" +
		std::format(L"{:08X}", dwDesiredAccess) + L"/" +
		std::format(L"{:08X}", dwCreationDisposition) + L"/" +
		std::format(L"{:08X}", dwFlagsAndAttributes) + L"/" +
		Core::Utils::GetSecurityDescriptorString(FileNameStr));

	return OriginalReturnValue;
}
