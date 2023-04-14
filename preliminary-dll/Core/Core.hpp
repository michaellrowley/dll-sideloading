#pragma once

#include <string>

namespace Core {
	namespace Logging {
		// Delete this error macro after defining the LogFilePath.
#error "Undefined LogFilePath in Core.hpp"
		// Don't include the extension as ...::Log() appends the PID to the filename.
		constexpr const char* const LogFilePath = "X:\\\\Your\\Path\\To\\logs";

		enum LogType {
			INITIAL_LOAD,
			HOOK_CREATED,
			LIBRARY_LOAD,
			LIBRARY_UNLOAD,
			FUNCTION_LOAD,
			PROCESS_SPAWN,
			FILE_LOAD, // FILE_OPEN is already reserved.
			CREATE_FILE, // FILE_CREATE is already reserved
		};

		void Log(Core::Logging::LogType Reason, const std::wstring& Information);
	};

	namespace Utils {
		std::wstring GetSecurityDescriptorString(const std::wstring& Path);
	};
};