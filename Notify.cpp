#include "Notify.hpp"
#include "ApcInjector.hpp"
#include "Log.hpp"

extern GlobalData* g_pGlobalData;

struct ProcessContext
{
	LIST_ENTRY		ListHeader;
	HANDLE			Pid;
	UNICODE_STRING	ProcessPath;
	UNICODE_STRING	ProcessCmdLine;
	BOOLEAN			bProtected;
	BOOLEAN			bIsWow64;
};

constexpr ULONG ProcessContextSize	= sizeof(ProcessContext);
constexpr ULONG ProcessContextTag	= 'pnCP';


static
VOID
AddProcessContext(
	IN CONST			PEPROCESS	Process,
	IN CONST			HANDLE		Pid, 
	IN OUT OPTIONAL		PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	ProcessContext* pProcessCtx = reinterpret_cast<ProcessContext*>(ExAllocateFromNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList));
	if (!pProcessCtx)
	{
		LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "ExAllocateFromNPagedLookasideList");
		return;
	}
	RtlZeroMemory(pProcessCtx, ProcessContextSize);

	pProcessCtx->Pid = Pid;
	pProcessCtx->bProtected = IsProtectedProcess(Process);

	if (g_pGlobalData->PsGetProcessWow64Process)
	{
		pProcessCtx->bIsWow64 = (g_pGlobalData->PsGetProcessWow64Process(Process) != nullptr);
	}

	do 
	{
		// process image file name
		pProcessCtx->ProcessPath.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(PagedPool, CreateInfo->ImageFileName->MaximumLength + sizeof(UNICODE_STRING), ProcessContextTag));
		if (pProcessCtx->ProcessPath.Buffer)
		{
			RtlZeroMemory(pProcessCtx->ProcessPath.Buffer, CreateInfo->ImageFileName->MaximumLength + sizeof(UNICODE_STRING));
			pProcessCtx->ProcessPath.Length = 0;
			pProcessCtx->ProcessPath.MaximumLength = CreateInfo->ImageFileName->MaximumLength;
			RtlCopyUnicodeString(&pProcessCtx->ProcessPath, CreateInfo->ImageFileName);
		}
		else
		{
			LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "ProcessCtx ProcessPath buffer alloc failed\r\n");
			break;
		}


		// process commandline
		pProcessCtx->ProcessCmdLine.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(PagedPool, CreateInfo->CommandLine->MaximumLength + sizeof(UNICODE_STRING), ProcessContextTag));
		if (pProcessCtx->ProcessCmdLine.Buffer)
		{
			RtlZeroMemory(pProcessCtx->ProcessCmdLine.Buffer, CreateInfo->CommandLine->MaximumLength + sizeof(UNICODE_STRING));
			pProcessCtx->ProcessCmdLine.Length = 0;
			pProcessCtx->ProcessCmdLine.MaximumLength = CreateInfo->CommandLine->MaximumLength;
			RtlCopyUnicodeString(&pProcessCtx->ProcessCmdLine, CreateInfo->CommandLine);
		}
		else
		{
			LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "ProcessCtx cmdline buffer alloc failed\r\n");
			break;
		}

		
		ExAcquireFastMutex(&g_pGlobalData->ProcessCtxFastMutex);

		InsertHeadList(&g_pGlobalData->ProcessCtxList, &pProcessCtx->ListHeader);

		ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);

		return;
	} while (FALSE);


	// failed 
	if (pProcessCtx->ProcessPath.Buffer)
	{
		ExFreePoolWithTag(pProcessCtx->ProcessPath.Buffer, ProcessContextTag);
		pProcessCtx->ProcessPath.Buffer = nullptr;
	}


	ExFreeToNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList, pProcessCtx);

}

static
VOID
DeleteProcessCtxByPid(IN CONST HANDLE ProcessId)
{
	if (!ProcessId || IsListEmpty(&g_pGlobalData->ProcessCtxList))
	{
		return;
	}

	PLIST_ENTRY pEntry = g_pGlobalData->ProcessCtxList.Flink;

	while (pEntry != &g_pGlobalData->ProcessCtxList)
	{
		ProcessContext* pNode = CONTAINING_RECORD(pEntry, ProcessContext, ListHeader);
		if (pNode)
		{
			if (ProcessId == pNode->Pid)
			{
				if (pNode->ProcessPath.Buffer)
				{
					ExFreePoolWithTag(pNode->ProcessPath.Buffer, ProcessContextTag);
					pNode->ProcessPath.Buffer = nullptr;
				}

				if (pNode->ProcessCmdLine.Buffer)
				{
					ExFreePoolWithTag(pNode->ProcessCmdLine.Buffer, ProcessContextTag);
					pNode->ProcessCmdLine.Buffer = nullptr;
				}

				ExAcquireFastMutex(&g_pGlobalData->ProcessCtxFastMutex);

				RemoveEntryList(&pNode->ListHeader);

				ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);


				ExFreeToNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList, pNode);

				break;
			}
		}

		pEntry = pEntry->Flink;
	}
}

ProcessContext*
FindProcessCtxByPid( IN CONST HANDLE Pid)
{
	if (!Pid || IsListEmpty(&g_pGlobalData->ProcessCtxList))
	{
		return nullptr;
	}

	ProcessContext*		pNode{ nullptr };
	PLIST_ENTRY			pEntry = g_pGlobalData->ProcessCtxList.Flink;

	ExAcquireFastMutex(&g_pGlobalData->ProcessCtxFastMutex);

	while (pEntry != &g_pGlobalData->ProcessCtxList)
	{
		pNode = CONTAINING_RECORD(pEntry, ProcessContext, ListHeader);
		if (pNode && (Pid == pNode->Pid))
		{
			ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
			return pNode;
		}

		pEntry = pEntry->Flink;
	}

	ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);

	return pNode;
}

static
VOID
CleanupProcessCtxList()
{
	while (!IsListEmpty(&g_pGlobalData->ProcessCtxList))
	{
		PLIST_ENTRY pEntry = g_pGlobalData->ProcessCtxList.Flink;
		ProcessContext* pNode = CONTAINING_RECORD(pEntry, ProcessContext, ListHeader);
		if (pNode)
		{

			if (pNode->ProcessPath.Buffer)
			{
				ExFreePoolWithTag(pNode->ProcessPath.Buffer, ProcessContextTag);
				pNode->ProcessPath.Buffer = nullptr;
			}

			if (pNode->ProcessCmdLine.Buffer)
			{
				ExFreePoolWithTag(pNode->ProcessCmdLine.Buffer, ProcessContextTag);
				pNode->ProcessCmdLine.Buffer = nullptr;
			}

			ExAcquireFastMutex(&g_pGlobalData->ProcessCtxFastMutex);

			RemoveEntryList(&pNode->ListHeader);

			ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
			
			ExFreeToNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList, pNode);
		}
	}
}


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

	if (CreateInfo)
	{
		if (CreateInfo->FileOpenNameAvailable)
		{
			// test ... .. .
			if (UnicodeStringContains(const_cast<PUNICODE_STRING>(CreateInfo->ImageFileName), L"mimikatz.exe"))
			{
				// block process create
				CreateInfo->CreationStatus = STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY;
				LOGINFO("[Block]block  mimikatz create\r\n");
				return;
			}

			AddProcessContext(Process, ProcessId, CreateInfo);
		}
	}
	else
	{
		DeleteProcessCtxByPid(ProcessId);
	}





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


// Test
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

	
	ProcessContext* pProcessContext{ nullptr };
	pProcessContext = FindProcessCtxByPid(ProcessId);
	if (pProcessContext)
	{
		
		if (pProcessContext->ProcessPath.Buffer)
		{
			if (KWstrnstr(pProcessContext->ProcessPath.Buffer, L"system32\\notepad.exe") &&
				KWstrnstr(FullImageName->Buffer, L"system32\\ntdll.dll"))
			{
				ApcInjectNativeProcess(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx64);
			}
			else 
			if (KWstrnstr(pProcessContext->ProcessPath.Buffer, L"SysWOW64\\notepad.exe") &&
				KWstrnstr(FullImageName->Buffer, L"SysWOW64\\ntdll.dll"))
			{				
				ApcInjectWow64Process(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx86);
			}
		}
	}
	else
	{
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
				ApcInjectNativeProcess(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx64);
			}
			else if (KWstrnstr(pProcessImage->Buffer, L"SysWOW64\\notepad.exe") &&
				KWstrnstr(FullImageName->Buffer, L"SysWOW64\\ntdll.dll"))
			{
				ApcInjectWow64Process(FullImageName, ProcessId, ImageInfo, &g_pGlobalData->InjectDllx86);
			}

			ExFreePool(pProcessImage);
			ObDereferenceObject(pProcess);
		}
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

	ExInitializeNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList,
		nullptr,
		nullptr,
		0,
		ProcessContextSize,
		ProcessContextTag, 
		0);

	InitializeListHead(&g_pGlobalData->ProcessCtxList);
	ExInitializeFastMutex(&g_pGlobalData->ProcessCtxFastMutex);


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

	CleanupProcessCtxList();

	ExDeleteNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList);

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
