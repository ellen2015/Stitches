#include "DeviceControl.hpp"
#include "Common.h"
#include "Imports.hpp"
#include "CRules.hpp"


extern GlobalData* g_pGlobalData;

#ifndef IS_MY_CONTROL_DEVICE_OBJECT
#define IS_MY_CONTROL_DEVICE_OBJECT(p) ((p) == g_pGlobalData->pDeviceObject)
#endif

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS 
DeviceControl::InitializeIoctlDevice(
	IN CONST PUNICODE_STRING DeviceName,
	IN CONST PUNICODE_STRING SymbolicLinkName)
{
	NTSTATUS status{STATUS_SUCCESS};

	__try
	{
		status = IoCreateDevice(g_pGlobalData->pDriverObject,
								0, 
								DeviceName,
								FILE_DEVICE_KERNELCODE, 
								FILE_DEVICE_SECURE_OPEN,
								FALSE, 
								&g_pGlobalData->pDeviceObject);
		if (NT_SUCCESS(status))
		{
			status = IoCreateSymbolicLink(SymbolicLinkName, DeviceName);
			if (NT_SUCCESS(status))
			{
				m_bSymbolicLinkCreated = TRUE;
			}
		}
	}
	__finally
	{
		if (!m_bSymbolicLinkCreated)
		{
			FinalizeIoctlDevice(DeviceName, SymbolicLinkName);
		}
	}



	return status;
}


VOID
DeviceControl::FinalizeIoctlDevice(
	IN CONST PUNICODE_STRING DeviceName,
	IN CONST PUNICODE_STRING SymbolicLinkName)
{
	UNREFERENCED_PARAMETER(DeviceName);
	UNREFERENCED_PARAMETER(SymbolicLinkName);

	if (!m_bSymbolicLinkCreated)
	{
		return;
	}

	IoDeleteSymbolicLink(SymbolicLinkName);

	if (g_pGlobalData->pDeviceObject)
	{
		IoDeleteDevice(g_pGlobalData->pDeviceObject);
	}

}


NTSTATUS
DriverDispatch(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	if (!IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject))
	{
		Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	NTSTATUS			status				{ STATUS_SUCCESS };
	PIO_STACK_LOCATION	pIrpStack			{ nullptr };
	PVOID				pIoBuffer			{ nullptr };
	ULONG				nInputbufferLength  { 0 };
	ULONG				nOutputbufferLength { 0 };


	pIrpStack = IoGetCurrentIrpStackLocation(Irp);

	pIoBuffer = Irp->AssociatedIrp.SystemBuffer;

	nInputbufferLength	= pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	nOutputbufferLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	// default setting
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	// 
	switch (pIrpStack->MajorFunction)
	{

	case IRP_MJ_DEVICE_CONTROL:
	{
		auto nIoctlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
		switch (nIoctlCode)
		{
		case IOCTL_STITCHES_ADD_TRUST_PROCESS:
		{
			WCHAR wszTrustProcess[MAX_PATH]{ 0 };
			if (nInputbufferLength < sizeof(wszTrustProcess) && 
				pIoBuffer)
			{
				RtlCopyMemory(wszTrustProcess, pIoBuffer, nInputbufferLength);
				Irp->IoStatus.Status = CRULES_ADD_TRUST_PROCESS(wszTrustProcess);
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}	
		}
		break;
		default:
			break;
		}
	}
	break;
	default:
		break;
	}

	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS 
DeviceControl::InitializeDriverDispatch()
{
	for (size_t i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		g_pGlobalData->pDriverObject->MajorFunction[i] = static_cast<PDRIVER_DISPATCH>(DriverDispatch);
	}

	return STATUS_SUCCESS;
}