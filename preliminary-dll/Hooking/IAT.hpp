#pragma once

#include <map>
#include <string>
#include <vector>
#include <windows.h>

namespace Hooking {
	namespace IAT {
		typedef std::map<std::string, PVOID> HookFunctionsMap;
		struct LibraryHookInfo {
			std::string LibraryName;
			HookFunctionsMap Functions;
		};
		void HookImports(const std::vector<Hooking::IAT::LibraryHookInfo>& Targets);
	};
};