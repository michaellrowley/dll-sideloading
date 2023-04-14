#include "./Core.hpp"

#include <Windows.h>

#include <string>
#include <fstream>
#include <mutex>
#include <map>

void Core::Logging::Log(Core::Logging::LogType Reason, const std::wstring& Information) {
	static std::mutex LoggingMutex;
	std::unique_lock CurrentLock(LoggingMutex);
	static std::wofstream OutputFile(Core::Logging::LogFilePath + std::string("-") + std::to_string(GetCurrentProcessId()) + ".txt");

	const std::map<Core::Logging::LogType, std::wstring> ReasonStringMap = {
		{ Core::Logging::LogType::INITIAL_LOAD, L"INITIALIZED" },
		{ Core::Logging::LogType::HOOK_CREATED, L"HOOKED"},
		{ Core::Logging::LogType::LIBRARY_LOAD, L"LoadLibrary" },
		{ Core::Logging::LogType::FUNCTION_LOAD, L"GetProcAddress" },
		{ Core::Logging::LogType::LIBRARY_UNLOAD, L"FreeLibrary" },
		{ Core::Logging::LogType::FILE_LOAD, L"OpenFile"},
		{ Core::Logging::LogType::CREATE_FILE, L"CreateFile"},
	};

	OutputFile << ReasonStringMap.at(Reason) + L"(" + Information + L")\n";
	OutputFile.flush();
}