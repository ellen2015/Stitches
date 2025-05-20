// StitchesApi.cpp : 定义 DLL 的导出函数。
//

#include "pch.h"
#include "framework.h"
#include "StitchesApi.h"
#include "Common.h"
#include "Sync.hpp"


using namespace StitchesApi;

static  AutoHandle	g_hDevice;

// 这是已导出类的构造函数。
CStitchesApi::CStitchesApi()
{
    return;
}

BOOLEAN 
STITCHESAPI_CC 
CStitchesApi::AddTrustProcess(CONST std::wstring& ProcessPath)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_ADD_TRUST_PROCESS,
		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(ProcessPath.c_str())),
		ProcessPath.length() * sizeof(WCHAR),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}


//STITCHESAPI_API
//BOOLEAN
//STITCHESAPI_NS
//AddTrustProcess(CONST std::wstring& ProcessPath)
//{
//	DWORD	dwBytesReturned{ 0 };
//	if (INVALID_HANDLE_VALUE == g_hDevice)
//	{
//		return FALSE;
//	}
//
//	if (!DeviceIoControl(g_hDevice,
//		IOCTL_STITCHES_ADD_TRUST_PROCESS,
//		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(ProcessPath.c_str())),
//		ProcessPath.length() * sizeof(WCHAR),
//		nullptr,
//		0,
//		&dwBytesReturned,
//		nullptr))
//	{
//		return FALSE;
//	}
//
//
//	return TRUE;
//}