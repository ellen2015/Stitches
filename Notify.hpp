#pragma once
#include "Imports.hpp"
#include "Log.hpp"
#include "Singleton.hpp"


class ThreadNotify
{
public:
	ThreadNotify()	= default;
	
	~ThreadNotify() = default;


	ThreadNotify(const ThreadNotify&)				= delete;
	ThreadNotify(ThreadNotify&&)					= delete;
	ThreadNotify& operator=(const ThreadNotify&)	= delete;

	NTSTATUS InitializeThreadNotify();

	NTSTATUS FinalizedThreadNotify();

	static VOID ThreadNotifyRoutine(
		IN HANDLE ProcessId,
		IN HANDLE ThreadId,
		IN BOOLEAN Create);

public:
	BOOLEAN		m_bInitialized{FALSE};
};

class ProcessNotify
{
public:
	ProcessNotify() = default;

	~ProcessNotify() = default;

	ProcessNotify(const ProcessNotify&)				= delete;
	ProcessNotify(ProcessNotify&&)					= delete;
	ProcessNotify& operator=(const ProcessNotify&)	= delete;

	NTSTATUS InitializeProcessNotify();

	NTSTATUS FinalizedProcessNotify();

	static VOID ProcessNotifyRoutine(
		IN OUT				PEPROCESS Process,
		IN OUT				HANDLE ProcessId,
		IN OUT OPTIONAL		PPS_CREATE_NOTIFY_INFO CreateInfo);

public:
	BOOLEAN		m_bInitialized{ FALSE };
};

class ImageNotify
{
public:
	ImageNotify() = default;

	~ImageNotify() = default;

	ImageNotify(const ImageNotify&) = delete;
	ImageNotify(ImageNotify&&) = delete;
	ImageNotify& operator=(const ImageNotify&) = delete;

	NTSTATUS InitializeImageNotify();

	NTSTATUS FinalizedImageNotify();

	static VOID ImageNotifyRoutine(
		_In_  PUNICODE_STRING FullImageName,
		_In_  HANDLE ProcessId,
		_In_  PIMAGE_INFO ImageInfo);

public:
	BOOLEAN		m_bInitialized{ FALSE };
};


class Notify : public Singleton<Notify>
{
public:
	VOID InitializedNotifys();
	VOID FinalizedNotifys();

private:
	ProcessNotify	m_ProcessNotify;
	ThreadNotify	m_ThreadNotify;
	ImageNotify		m_ImageNotify;
};

