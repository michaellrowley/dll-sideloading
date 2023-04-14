#pragma once

#include <Windows.h>
#include <Winternl.h>

#include <map>
#include <string>

namespace Hooking {
	namespace Interception {
		void SetCallbackOrigin(std::string FunctionName, PVOID OriginalAddress);

		HMODULE __stdcall LoadLibraryExA_Hook(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
		HMODULE __stdcall LoadLibraryA_Hook(LPCSTR lpLibFileName);

		HMODULE __stdcall LoadLibraryExW_Hook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
		HMODULE __stdcall LoadLibraryW_Hook(LPCWSTR lpLibFileName);

		FARPROC __stdcall GetProcAddress_Hook(HMODULE hModule, LPCSTR lpProcName);

		BOOL __stdcall FreeLibrary_Hook(HMODULE hLibModule);

		HFILE __stdcall OpenFile_Hook(LPCSTR lpFileName, LPOFSTRUCT lpReOpenBuff, UINT uStyle);

		HANDLE __stdcall CreateFileA_Hook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
			LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
			HANDLE hTemplateFile);
		HANDLE __stdcall CreateFileW_Hook(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
			LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
			HANDLE hTemplateFile);
	};
};