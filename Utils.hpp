#pragma once
#include "Imports.hpp"

WCHAR*
KWstrnstr(
	const WCHAR* src,
	const WCHAR* find);

PVOID 
KGetProcAddress(
	IN CONST HANDLE ModuleHandle, 
	CONST PCHAR FuncName);


NTSTATUS 
GetProcessImageByPid(
	IN CONST HANDLE Pid, 
	IN OUT PWCHAR ProcessImage);

