#include "Utils.hpp"


WCHAR*
KWstrnstr(
	const WCHAR* src,
	const WCHAR* find)
{
	WCHAR* cp = (WCHAR*)src;
	WCHAR* s1 = NULL, * s2 = NULL;

	if (NULL == src ||
		NULL == find)
	{
		return NULL;
	}

	while (*cp)
	{
		s1 = cp;
		s2 = (WCHAR*)find;

		while (*s2 && *s1 && !(towlower(*s1) - towlower(*s2)))
		{
			s1++, s2++;
		}

		if (!(*s2))
		{
			return cp;
		}

		cp++;
	}
	return NULL;
}


PVOID
KGetProcAddress(
	IN CONST HANDLE ModuleHandle,
	CONST PCHAR FuncName)
{
	PIMAGE_DOS_HEADER       DosHeader = NULL;
	PIMAGE_NT_HEADERS       NtHeader = NULL;
	PIMAGE_DATA_DIRECTORY   ExportsDir = NULL;
	PIMAGE_EXPORT_DIRECTORY Exports = NULL;
#ifdef _WIN64
	PIMAGE_NT_HEADERS32		pNtHeaders32;
#endif
	PULONG Functions = NULL;
	PSHORT Ordinals = NULL;
	PULONG Names = NULL;
	ULONG64 ProcAddr = 0;
	ULONG NumOfFunc = 0;

	ULONG i = 0, NumOfNames = 0, iOrd = 0, nSize = 0, ulImageSize = 0;

	if (!ModuleHandle || !FuncName)
	{
		return NULL;
	}

	DosHeader = (PIMAGE_DOS_HEADER)ModuleHandle;

	NtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleHandle + DosHeader->e_lfanew);

	if (!NtHeader)
	{
		return NULL;
	}
#ifdef _WIN64
	if (NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		ExportsDir = NtHeader->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
		ulImageSize = NtHeader->OptionalHeader.SizeOfImage;
	}
	else
	{
		pNtHeaders32 = (PIMAGE_NT_HEADERS32)NtHeader;
		ExportsDir = pNtHeaders32->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
		ulImageSize = NtHeader->OptionalHeader.SizeOfImage;
	}
#else
	ExportsDir = NtHeader->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	ulImageSize = NtHeader->OptionalHeader.SizeOfImage;
#endif 
	if (!ExportsDir)
	{
		return NULL;
	}

	Exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleHandle + ExportsDir->VirtualAddress);

	if (!Exports)
	{
		return NULL;
	}

	Functions = (PULONG)((PUCHAR)ModuleHandle + Exports->AddressOfFunctions);
	Ordinals = (PSHORT)((PUCHAR)ModuleHandle + Exports->AddressOfNameOrdinals);
	Names = (PULONG)((PUCHAR)ModuleHandle + Exports->AddressOfNames);

	NumOfNames = Exports->NumberOfNames;
	ProcAddr = ExportsDir->VirtualAddress;
	NumOfFunc = Exports->NumberOfFunctions;

	nSize = ExportsDir->Size;
	__try
	{
		for (i = 0; i < NumOfNames; i++)
		{
			iOrd = Ordinals[i];
			if (iOrd >= NumOfFunc)
			{
				continue;
			}

			if (Functions[iOrd] > 0 && Functions[iOrd] < ulImageSize)
			{
				if (_stricmp((char*)ModuleHandle + Names[i], FuncName) == 0)
				{
					return (PVOID)((char*)ModuleHandle + Functions[iOrd]);
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	return NULL;
}
