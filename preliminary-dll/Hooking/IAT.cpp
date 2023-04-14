#include <Windows.h>

#include "IAT.hpp"
#include "../Core/Core.hpp"
#include "Interception.hpp"

#include <string>
#include <format>
#include <vector>
#include <functional>
#include <map>
#include <stdexcept>
#include <iostream>

void Hooking::IAT::HookImports(const std::vector<Hooking::IAT::LibraryHookInfo>& Targets) {
	// Might be worth looking into suspending the process before getting to WriteProcessMemory!

	ULONGLONG CurrentImageBase = reinterpret_cast<DWORDLONG>(GetModuleHandleA(nullptr));
	static const HANDLE CurrentProcessHandle = GetCurrentProcess();
	if (CurrentImageBase == 0x00000000) {
		// Could use GetLastError for more information.
		throw std::runtime_error("Unable to get local handle");
	}
	PIMAGE_DOS_HEADER CurrentImageHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(CurrentImageBase);
	if (CurrentImageHeader->e_magic != 0x5A4D) {
		throw std::runtime_error("Unable to validate local handle");
	}
	PIMAGE_NT_HEADERS CurrentPEHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(CurrentImageBase + CurrentImageHeader->e_lfanew);
	if (CurrentPEHeader == nullptr) {
		throw std::runtime_error("Unable to get local PE header");
	}
	IMAGE_DATA_DIRECTORY ImportDirectory = CurrentPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (ImportDirectory.VirtualAddress == 0x00000000 || ImportDirectory.Size == 0) {
		throw std::runtime_error("Unable to get local PE IAT");
	}
	for (PIMAGE_IMPORT_DESCRIPTOR IterativeLibrary = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ImportDirectory.VirtualAddress + CurrentImageBase);
		IterativeLibrary->Characteristics != NULL; IterativeLibrary++) {

		const std::string LibraryName = std::string(reinterpret_cast<PCHAR>(IterativeLibrary->Name + CurrentImageBase));
		const Hooking::IAT::HookFunctionsMap* ApplicableFunctions = nullptr;
		for (const Hooking::IAT::LibraryHookInfo& IterativeTargetLibrary : Targets) {
			if (IterativeTargetLibrary.LibraryName == LibraryName) {
				ApplicableFunctions = &IterativeTargetLibrary.Functions;
				break;
			}
		}
		if (ApplicableFunctions == nullptr) {
			continue;
		}

		for (PIMAGE_THUNK_DATA ImgThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(CurrentImageBase + IterativeLibrary->FirstThunk),
			ImgOriginalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(CurrentImageBase + IterativeLibrary->OriginalFirstThunk);
			ImgOriginalThunk->u1.AddressOfData != 0x00000000; ImgThunk++, ImgOriginalThunk++) {

			std::string ImportMatchStr;
			if (ImgOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				const std::string OrdinalStr = std::to_string(IMAGE_ORDINAL(ImgOriginalThunk->u1.Ordinal));
				ImportMatchStr = "#" + OrdinalStr;
			}
			else {
				PIMAGE_IMPORT_BY_NAME FunctionData = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(CurrentImageBase + ImgOriginalThunk->u1.AddressOfData);
				ImportMatchStr = FunctionData->Name;
			}

			const Hooking::IAT::HookFunctionsMap::const_iterator TargetInstance = ApplicableFunctions->find(ImportMatchStr);
			if (TargetInstance == ApplicableFunctions->cend()) {
				continue;
			}
			DWORD OldProtection = NULL;
			BOOL Success = VirtualProtect(&ImgThunk->u1.Function, sizeof(TargetInstance->second), PAGE_READWRITE, &OldProtection);
			Hooking::Interception::SetCallbackOrigin(ImportMatchStr, reinterpret_cast<PVOID>(ImgThunk->u1.Function));
			Success &= WriteProcessMemory(CurrentProcessHandle, &ImgThunk->u1.Function, &TargetInstance->second, sizeof(TargetInstance->second), NULL);
			// PAGE_READONLY is the default protection for the IAT, I've double checked this.
			Success &= VirtualProtect(&ImgThunk->u1.Function, sizeof(TargetInstance->second), PAGE_READONLY, &OldProtection);
			if (!Success) {
				throw std::runtime_error("Failed writing new function pointer to IAT");
			}
			Core::Logging::Log(Core::Logging::LogType::HOOK_CREATED,
				L"Library='" + std::wstring(LibraryName.cbegin(), LibraryName.cend()) + L"'"
				L", Function='" + std::wstring(ImportMatchStr.cbegin(), ImportMatchStr.cend()) + L"'"
				L", Address='" + std::format(L"{:08X}", reinterpret_cast<DWORD>(reinterpret_cast<PVOID>(ImgThunk->u1.Function))) + L"'");
		}
	}
}