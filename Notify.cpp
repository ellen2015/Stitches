#include "Notify.hpp"
#include "ApcInjector.hpp"
#include "Log.hpp"

extern GlobalData* g_pGlobalData;


static
VOID
PcreateProcessNotifyRoutineEx(
	IN OUT				PEPROCESS Process,
	IN OUT				HANDLE ProcessId,
	IN OUT OPTIONAL		PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(CreateInfo);
}

static
VOID
PCreateThreadNotifyRoutine(
	IN HANDLE ProcessId,
	IN HANDLE ThreadId,
	IN BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);


	if (Create)
	{
		// 这里需要注意  还是需要配合进程上下文使用
		// 因为这样的判断会导致 父进程创建子进程的情况
		// 最好是判断父进程pid是否和processid相等的情况
		auto bRemoteThread = [&]() { return (PsGetCurrentProcessId() != ProcessId) &&
			(PsInitialSystemProcess != PsGetCurrentProcessId()) &&
			(ProcessId != PsGetProcessId(PsInitialSystemProcess));
		};

		if (bRemoteThread())
		{
			WCHAR wszProcessPath[MAX_PATH] = { 0 };

			GetProcessImageByPid(ProcessId, wszProcessPath);

			WCHAR wszFxxk[MAX_PATH] = { 0 };
			GetProcessImageByPid(PsGetCurrentProcessId(), wszFxxk);
			
			LOGINFO("[Fxxk] Process : %ws --- Remote Thread : %d Remote Process %d - ProcessPath : %ws\n", wszFxxk, ThreadId, ProcessId, wszProcessPath);

		}
	}


}


// ����
static
VOID
PloadImageNotifyRoutine(
	_In_  PUNICODE_STRING FullImageName,
	_In_  HANDLE ProcessId,
	_In_  PIMAGE_INFO ImageInfo
)
{
	if (HandleToULong(ProcessId) <= 4)
	{
		return;
	}

	NTSTATUS status{ STATUS_SUCCESS };
	PUNICODE_STRING pProcessImage{ nullptr };
	PEPROCESS pProcess{ nullptr };
	status = PsLookupProcessByProcessId(ProcessId, &pProcess);
	if (!NT_SUCCESS(status))
	{
		return;
	}

	status = SeLocateProcessImageName(pProcess, &pProcessImage);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pProcess);
		return;
	}

	// test ... .. .
	if (pProcessImage && pProcessImage->Buffer)
	{
		if (KWstrnstr(pProcessImage->Buffer, L"system32\\notepad.exe") &&
			KWstrnstr(FullImageName->Buffer, L"system32\\ntdll.dll"))
		{
			//DbgBreakPoint();
			ApcInjectNativeProcess(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx64);
		}
		else if (KWstrnstr(pProcessImage->Buffer, L"SysWOW64\\notepad.exe") &&
			KWstrnstr(FullImageName->Buffer, L"SysWOW64\\ntdll.dll"))
		{
			//DbgBreakPoint();
			ApcInjectWow64Process(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx86);
		}

		ExFreePool(pProcessImage);
		ObDereferenceObject(pProcess);
	}

}

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS InitializeNotify()
{
	NTSTATUS status{ STATUS_SUCCESS };

	//DbgBreakPoint();

	// check Notify initial
	if (g_pGlobalData->bNoptifyIntialized)
	{
		return STATUS_SUCCESS;
	}


	// process notify
	UNICODE_STRING ustrFunc;

#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
	RtlUnicodeStringInit(&ustrFunc, L"PsSetCreateProcessNotifyRoutineEx2");

	g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx2 = reinterpret_cast<PfnPsSetCreateProcessNotifyRoutineEx2>(MmGetSystemRoutineAddress(&ustrFunc));
	if (g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx2)
	{
		status = g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx2(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(PcreateProcessNotifyRoutineEx),
			FALSE);
	}

#else
	RtlUnicodeStringInit(&ustrFunc, L"PsSetCreateProcessNotifyRoutineEx");
	g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx = reinterpret_cast<PfnPsSetCreateProcessNotifyRoutineEx>(MmGetSystemRoutineAddress(&ustrFunc));
	if (g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx)
	{
		status = g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(PcreateProcessNotifyRoutineEx),
			FALSE);
	}
#endif

	
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "Process Notify Created failed\r\n");
		return status;
	}

	// Thread Notify
	status = PsSetCreateThreadNotifyRoutine(reinterpret_cast<PCREATE_THREAD_NOTIFY_ROUTINE>(PCreateThreadNotifyRoutine));
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "Thread Notify Created failed\r\n");
		goto THREAD_FAIL;
	}


	// Image Notify
	status = PsSetLoadImageNotifyRoutine(reinterpret_cast<PLOAD_IMAGE_NOTIFY_ROUTINE>(PloadImageNotifyRoutine));
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "Image Notify Created failed\r\n");
		goto IMAGE_FIAL;
	}

	g_pGlobalData->bNoptifyIntialized = TRUE;
	return status;


IMAGE_FIAL:
	status = PsRemoveCreateThreadNotifyRoutine(reinterpret_cast<PCREATE_THREAD_NOTIFY_ROUTINE>(PCreateThreadNotifyRoutine));

THREAD_FAIL:
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
	if (g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx2)
	{
		status = g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(PcreateProcessNotifyRoutineEx),
			TRUE);
	}
#else
	if (g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx)
	{
		status = g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(PcreateProcessNotifyRoutineEx),
			TRUE);
	}
#endif
	return status;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS FinalizeNotify()
{
	NTSTATUS status{ STATUS_SUCCESS };

	if (!g_pGlobalData->bNoptifyIntialized)
	{
		return STATUS_SUCCESS;
	}


#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
	if (g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx2)
	{
		status = g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(PcreateProcessNotifyRoutineEx),
			TRUE);
	}
#else
	if (g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx)
	{
		status = g_pGlobalData->pfnPsSetCreateProcessNotifyRoutineEx(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE_EX>(PcreateProcessNotifyRoutineEx),
			TRUE);
	}
#endif

	status = PsRemoveCreateThreadNotifyRoutine(reinterpret_cast<PCREATE_THREAD_NOTIFY_ROUTINE>(PCreateThreadNotifyRoutine));


	status = PsRemoveLoadImageNotifyRoutine(reinterpret_cast<PLOAD_IMAGE_NOTIFY_ROUTINE>(PloadImageNotifyRoutine));

	return status;
}
