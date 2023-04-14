#include "./Core.hpp"

#include <Windows.h>
#include <sddl.h>

#include <exception>
#include <format>
#include <memory>
#include <string>

// https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information
#define DLL_DESCRIPTOR_SECINFO OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION

std::wstring Core::Utils::GetSecurityDescriptorString(const std::wstring& Path) {
	DWORD BytesRequired = 0;
	GetFileSecurityW(Path.c_str(), DLL_DESCRIPTOR_SECINFO, nullptr, 0, &BytesRequired);
	std::unique_ptr<std::uint8_t[]> UnderlyingSecurityDescriptorBuffer = std::make_unique<std::uint8_t[]>(BytesRequired);
	SECURITY_DESCRIPTOR* const DLLSecurityDescriptor = reinterpret_cast<SECURITY_DESCRIPTOR*>(UnderlyingSecurityDescriptorBuffer.get());
	if (GetFileSecurityW(Path.c_str(), DLL_DESCRIPTOR_SECINFO, DLLSecurityDescriptor, BytesRequired, &BytesRequired)) {
		LPWSTR DescriptorString = nullptr;
		ULONG DescriptorStringLength = 0;
		// How long is this function name?!
		if (ConvertSecurityDescriptorToStringSecurityDescriptorW(DLLSecurityDescriptor, SDDL_REVISION_1, DLL_DESCRIPTOR_SECINFO, &DescriptorString, &DescriptorStringLength)) {
			std::wstring RetVal(DescriptorString);
			LocalFree(DescriptorString);
			return RetVal;
		}
	}

	return std::wstring(L"(UNKNOWN - SDDL)"); // Throwing would just add overhead to minimal benefit
}