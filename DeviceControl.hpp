#pragma once
#include "Singleton.hpp"


class DeviceControl : public Singleton<DeviceControl>
{
public:
	_Function_class_(DRIVER_INITIALIZE)
		_IRQL_requires_same_
		_IRQL_requires_(PASSIVE_LEVEL)
		NTSTATUS InitializeDriverDispatch();



	VOID
		FinalizeIoctlDevice(
			IN CONST PUNICODE_STRING DeviceName,
			IN CONST PUNICODE_STRING SymbolicLinkName);


	_Function_class_(DRIVER_INITIALIZE)
		_IRQL_requires_same_
		_IRQL_requires_(PASSIVE_LEVEL)
		NTSTATUS
		InitializeIoctlDevice(
			IN CONST PUNICODE_STRING DeviceName,
			IN CONST PUNICODE_STRING SymbolicLinkName);
private:
	BOOLEAN m_bSymbolicLinkCreated{ FALSE };
};

#define DEVICE_CTL_INSTANCE()			(DeviceControl::getInstance())
#define DEVICE_CTL_INITIALIZED(a, b)	(DeviceControl::getInstance()->InitializeIoctlDevice((a), (b)))
#define DEVICE_CTL_FINALIZED(a, b)		(DeviceControl::getInstance()->FinalizeIoctlDevice((a), (b)))
#define DEVICE_INITIALIZED_DISPATCH()	(DeviceControl::getInstance()->InitializeDriverDispatch())

