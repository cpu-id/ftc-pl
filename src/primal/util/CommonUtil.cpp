#include "CommonUtil.hpp"

HMODULE CommonUtil::GetModule (const char* module) {

    HMODULE hModule = GetModuleHandleA (module);

    return hModule ? LoadLibraryA (module) : hModule;
}

MODULEINFO CommonUtil::GetModuleInfo (const char* module) {

    //Docs: https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation.
    MODULEINFO moduleInfo = { nullptr };

    GetModuleInformation (GetCurrentProcess (), CommonUtil::GetModule (module), &moduleInfo, sizeof (MODULEINFO));

    return moduleInfo;
}

FARPROC CommonUtil::GetOrLoadFunction (const char* module, const char* function) {
    return GetProcAddress (CommonUtil::GetModule (module), function);
}

int CommonUtil::SearchSignature (const char* module, const char* signature) {

    //Fastest IDA-Style sigsearch.
    //Source code: https://github.com/learn-more/findpattern-bench/blob/master/patterns/learn_more.h#L75.
    //Benchmark: https://github.com/learn-more/findpattern-bench/blob/master/results.txt#L9.
    //Author: learn_more.

    auto IsPatternMatch = [](const unsigned char* address, const unsigned char* pattern, const unsigned char* mask) {

        size_t sizeSpaceIterator = 0;

        while (address [sizeSpaceIterator] == pattern [sizeSpaceIterator] || mask [sizeSpaceIterator] == static_cast <unsigned char> ('?')) {

            if (!mask [++sizeSpaceIterator]) {
                return true;
            }

        }

        return false;
    };

    MODULEINFO moduleInfo = GetModuleInfo (module);

    size_t signatureLength = std::strlen (signature);

    unsigned char* patternBase = static_cast <unsigned char*> (_alloca (signatureLength >> 1));
    unsigned char* maskBase = static_cast <unsigned char*> (_alloca (signatureLength >> 1));
    unsigned char* pattern = patternBase;
    unsigned char* mask = maskBase;

    signatureLength = 0;

    while (*signature) {

        if (*signature == ' ') signature++;
        if (!*signature) break;

        if (*signature == static_cast <unsigned char> ('\?')) {

            *pattern++ = 0;
            *mask++ = '?';
            signature += ((*signature == static_cast <unsigned short> ('\?\?')) ? 2 : 1);

        } else {

            *pattern++ = GET_BYTE (signature);
            *mask++ = 'x';
            signature += 2;

        }
        signatureLength++;
    }

    *mask = 0;
    pattern = patternBase;
    mask = maskBase;

    for (int searchIterator = 0; searchIterator < (moduleInfo.SizeOfImage - signatureLength); ++searchIterator) {

        if (IsPatternMatch (static_cast <unsigned char*> (moduleInfo.lpBaseOfDll) + searchIterator, patternBase, maskBase)) {
            return reinterpret_cast <int> (moduleInfo.lpBaseOfDll) + searchIterator;
        }

    }

    return NULL;

}

int CommonUtil::GetChildProcessID (std::string process) {
	
	//Orignal source: https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes.
	
	//Take snapshot of all x32 process.
	HANDLE snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
	
	//Setup processEntry structure.
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof (PROCESSENTRY32);
	
	//Check if first process valid.
	if (Process32First (snapshot,&pe32)) {
		
		//Iterate all process.
		while (Process32Next (snapshot, &pe32)) {
			
			//Cmp process name with target & check process id not equals.
			if (!strcmp (pe32.szExeFile, process.c_str ()) && pe32.th32ProcessID != GetCurrentProcessId ()) {
				
				//Close snapshot handle.
				CloseHandle (snapshot);
				
				//Return iterate process id.
				return pe32.th32ProcessID;
			}
			
		}
		
	}
		
	//Close snapshot handle.
	CloseHandle (snapshot);
	
	//Return zero.
	return NULL;
	
}