#include "ApcInjector.hpp"
#include "Utils.hpp"
#include "Notify.hpp"
#include "New.hpp"
#include "ProcessProtector.hpp"


HANDLE g_hFile {nullptr};

GlobalData* g_pGlobalData;

VOID
InitSystemFucAddr()
{
	UNICODE_STRING ustrPsIsProtectedProcess{};
	RtlInitUnicodeString(&ustrPsIsProtectedProcess, L"PsIsProtectedProcess");	
	g_pGlobalData->PsIsProtectedProcess = reinterpret_cast<PPsIsProtectedProcess>(MmGetSystemRoutineAddress(&ustrPsIsProtectedProcess));

	UNICODE_STRING ustrPsIsProtectedProcessLight{};
	RtlInitUnicodeString(&ustrPsIsProtectedProcessLight, L"PsIsProtectedProcessLight");
	g_pGlobalData->PsIsProtectedProcessLight = reinterpret_cast<PPsIsProtectedProcessLight>(MmGetSystemRoutineAddress(&ustrPsIsProtectedProcessLight));

	UNICODE_STRING ustrZwTerminateProcess{};
	RtlInitUnicodeString(&ustrZwTerminateProcess, ZWTERMINATEPROCESS);
	g_pGlobalData->ZwTerminateProcess = reinterpret_cast<PfnZwTerminateProcess>(MmGetSystemRoutineAddress(&ustrZwTerminateProcess));


	UNICODE_STRING ustrPsGetProcessWow64Process;
	RtlInitUnicodeString(&ustrPsGetProcessWow64Process, L"PsGetProcessWow64Process");
	g_pGlobalData->PsGetProcessWow64Process = reinterpret_cast<PPsGetProcessWow64Process>(MmGetSystemRoutineAddress(&ustrPsGetProcessWow64Process));

	UNICODE_STRING ustrPsSetCreateProcessNotifyRoutine;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
	RtlUnicodeStringInit(&ustrPsSetCreateProcessNotifyRoutine, L"PsSetCreateProcessNotifyRoutineEx2");

	g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx2 = reinterpret_cast<PfnPsSetCreateProcessNotifyRoutineEx2>(MmGetSystemRoutineAddress(&ustrPsSetCreateProcessNotifyRoutine));
	

#else
	RtlUnicodeStringInit(&ustrPsSetCreateProcessNotifyRoutine, L"PsSetCreateProcessNotifyRoutineEx");
	g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx = reinterpret_cast<PfnPsSetCreateProcessNotifyRoutineEx>(MmGetSystemRoutineAddress(&ustrPsSetCreateProcessNotifyRoutine));
	
#endif

}


EXTERN_C
{
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath);

VOID
DriverUnload(PDRIVER_OBJECT DriverObject);

};

#if defined(ALLOC_PRAGMA)

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)

#endif


VOID
DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	if (g_hFile)
	{
		ZwClose(g_hFile);
		g_hFile = nullptr;
	}

	
	Notify::getInstance()->FinalizedNotifys();
	delete Notify::getInstance();

	FinalizeObRegisterCallbacks();

	if (g_pGlobalData)
	{

		if (g_pGlobalData->InjectDllx64.Buffer)
		{
			ExFreePoolWithTag(g_pGlobalData->InjectDllx64.Buffer, GLOBALDATA_TAG);
			g_pGlobalData->InjectDllx64.Buffer = nullptr;
		}
		if (g_pGlobalData->InjectDllx86.Buffer)
		{
			ExFreePoolWithTag(g_pGlobalData->InjectDllx86.Buffer, GLOBALDATA_TAG);
			g_pGlobalData->InjectDllx86.Buffer = nullptr;
		}


		delete g_pGlobalData;
		g_pGlobalData = nullptr;
	}
}

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status{ STATUS_SUCCESS };


	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	g_pGlobalData = new(NonPagedPoolNx) GlobalData;
	if (!g_pGlobalData)
	{
		DbgPrint("g_pGlobalData alloc failed\r\n");
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(g_pGlobalData, sizeof(GlobalData));

	DriverObject->DriverUnload = DriverUnload;
	status = InitializeLogFile(L"\\??\\C:\\desktop\\Log.txt");
	if (!NT_SUCCESS(status))
	{
		DbgPrint("status = %08X\r\n", status);
		if (g_pGlobalData)
		{
			delete g_pGlobalData;
			g_pGlobalData = nullptr;
		}

		return status;
	}

	// test 
	// 需要根据业务设置注入dll 路径
	// 不能以下方方式进行初始化全局变量中的字段 
	/*RtlInitUnicodeString(&g_pGlobalData->InjectDllx64, L"C:\\InjectDir\\InjectDll_x64.dll");
	RtlInitUnicodeString(&g_pGlobalData->InjectDllx86, L"C:\\InjectDir\\InjectDll_x86.dll");*/

	UNICODE_STRING ustrDllx64;
	RtlInitUnicodeString(&ustrDllx64, L"C:\\InjectDir\\InjectDll_x64.dll");

	UNICODE_STRING ustrDllx86;
	RtlInitUnicodeString(&ustrDllx86, L"C:\\InjectDir\\InjectDll_x86.dll");

	ULONG nAllocDllLength = ustrDllx64.MaximumLength;
	g_pGlobalData->InjectDllx64.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, nAllocDllLength, GLOBALDATA_TAG));
	if (g_pGlobalData->InjectDllx64.Buffer)
	{
		RtlZeroMemory(g_pGlobalData->InjectDllx64.Buffer, nAllocDllLength);
		g_pGlobalData->InjectDllx64.Length = 0;
		g_pGlobalData->InjectDllx64.MaximumLength = ustrDllx64.MaximumLength;
		RtlCopyUnicodeString(&g_pGlobalData->InjectDllx64, &ustrDllx64);
	}
	else
	{
		LOGERROR(STATUS_NO_MEMORY, "g_pGlobalData->InjectDllx64.Buffer alloc faid\r\n");
	}

	nAllocDllLength = ustrDllx86.MaximumLength;
	g_pGlobalData->InjectDllx86.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, nAllocDllLength, GLOBALDATA_TAG));
	if (g_pGlobalData->InjectDllx86.Buffer)
	{
		RtlZeroMemory(g_pGlobalData->InjectDllx86.Buffer, nAllocDllLength);
		g_pGlobalData->InjectDllx86.Length = 0;
		g_pGlobalData->InjectDllx86.MaximumLength = ustrDllx86.MaximumLength;
		RtlCopyUnicodeString(&g_pGlobalData->InjectDllx86, &ustrDllx86);
	}
	else
	{
		LOGERROR(STATUS_NO_MEMORY, "g_pGlobalData->InjectDllx86.Buffer alloc faid\r\n");
	}


	InitSystemFucAddr();


	Notify::getInstance()->InitializedNotifys();

	InitializeObRegisterCallbacks();


	return status;
}