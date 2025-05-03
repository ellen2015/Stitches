#pragma once
#include "Imports.hpp"
#include "New.hpp"

template <class T, typename _Compare>
class GenericTable
{
public:
	GenericTable();
	~GenericTable();


	GenericTable(const GenericTable&) = delete;
	GenericTable& operator=(const GenericTable&) = delete;

	static
		RTL_GENERIC_COMPARE_RESULTS
		CompareRoutine(
			__in struct _RTL_GENERIC_TABLE* Table,
			__in PVOID  FirstStruct,
			__in PVOID  SecondStruct);

	static
		PVOID
		AllocateRoutine(
			__in struct _RTL_GENERIC_TABLE* Table,
			__in CLONG  ByteSize);

	static
		VOID
		FreeRoutine(
			__in struct _RTL_GENERIC_TABLE* Table,
			__in PVOID  Buffer);

	NTSTATUS	AddElement(T& Data);
	NTSTATUS	DelElement(T& Data);
	BOOLEAN		IsInTable(T& Data);

	PVOID		FindElement(T& findBuffer);

	VOID		ClearAllElements();
private:
	VOID Init();
	VOID Finalized();



private:
	RTL_GENERIC_TABLE	m_GenericTable{};
	FAST_MUTEX			m_FastMutex{};
	_Compare			m_Compare;
};

template <class T, typename _Compare>
PVOID GenericTable<T, _Compare>::FindElement(T& findBuffer)
{
	PVOID pNode = nullptr;
	ExAcquireFastMutex(&m_FastMutex);

	pNode = RtlLookupElementGenericTable(&m_GenericTable, reinterpret_cast<PVOID>(&findBuffer));

	ExReleaseFastMutex(&m_FastMutex);

	return pNode;
}

template <class T, typename _Compare>
BOOLEAN GenericTable<T, _Compare>::IsInTable(T& Data)
{
	BOOLEAN bIsInTable = FALSE;

	PVOID pNode = nullptr;
	ExAcquireFastMutex(&m_FastMutex);

	pNode = RtlLookupElementGenericTable(&m_GenericTable, reinterpret_cast<PVOID>(&Data));
	if (pNode)
	{
		bIsInTable = TRUE;
	}


	ExReleaseFastMutex(&m_FastMutex);


	return bIsInTable;
}

template <class T, typename _Compare>
VOID GenericTable<T, _Compare>::ClearAllElements()
{
	PVOID pNode = nullptr;

	ExAcquireFastMutex(&m_FastMutex);

	while ((pNode = RtlGetElementGenericTable(&m_GenericTable, 0)) != nullptr)
	{
		RtlDeleteElementGenericTable(&m_GenericTable, pNode);
	}


	ExReleaseFastMutex(&m_FastMutex);
}

template <class T, typename _Compare>
NTSTATUS GenericTable<T, _Compare>::DelElement(T& Data)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pNode = nullptr;
	ExAcquireFastMutex(&m_FastMutex);

	pNode = RtlLookupElementGenericTable(&m_GenericTable, reinterpret_cast<PVOID>(&Data));
	if (pNode)
	{
		if (RtlDeleteElementGenericTable(&m_GenericTable, reinterpret_cast<PVOID>(&Data)))
		{
#ifdef DBG
			DbgPrint("Element was Delete success\r\n");
			//LOGINFO("Element was Delete success\r\n");
#endif
			status = STATUS_SUCCESS;
		}
	}
	else
	{
#ifdef DBG
		DbgPrint("Element was not existed\r\n");
#endif

	}

	ExReleaseFastMutex(&m_FastMutex);

	return status;
}

template <class T, typename _Compare>
NTSTATUS GenericTable<T, _Compare>::AddElement(T& Data)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pNode = nullptr;
	ExAcquireFastMutex(&m_FastMutex);

	pNode = RtlLookupElementGenericTable(&m_GenericTable, reinterpret_cast<PVOID>(&Data));
	if (!pNode)
	{
		if (RtlInsertElementGenericTable(&m_GenericTable, reinterpret_cast<PVOID>(&Data), sizeof(T), nullptr))
		{
#ifdef DBG
			DbgPrint("Element was Insert success\r\n");
			//LOGINFO("Add elemenet success\r\n");
#endif
			status = STATUS_SUCCESS;
		}
	}
	else
	{
#ifdef DBG
		//DbgBreakPoint();
		DbgPrint("Element was existed \r\n");

#endif

	}

	ExReleaseFastMutex(&m_FastMutex);

	return status;
}

template <class T, typename _Compare>
VOID GenericTable<T, _Compare>::FreeRoutine(
	__in struct _RTL_GENERIC_TABLE* Table,
	__in PVOID Buffer)
{
	UNREFERENCED_PARAMETER(Table);
	delete[] Buffer;
}

template <class T, typename _Compare>
PVOID GenericTable<T, _Compare>::AllocateRoutine(
	__in struct _RTL_GENERIC_TABLE* Table,
	__in CLONG ByteSize)
{
	UNREFERENCED_PARAMETER(Table);
	return new(NonPagedPoolNx) UCHAR[ByteSize];
}

template <class T, typename _Compare>
RTL_GENERIC_COMPARE_RESULTS GenericTable<T, _Compare>::CompareRoutine(
	__in struct _RTL_GENERIC_TABLE* Table,
	__in PVOID FirstStruct,
	__in PVOID SecondStruct)
{
	GenericTable* gtbl = CONTAINING_RECORD(Table, GenericTable, m_GenericTable);

	NT_ASSERT(MmIsAddressValid(gtbl));

	return gtbl->m_Compare(FirstStruct, SecondStruct);
}

template <class T, typename _Compare>
VOID GenericTable<T, _Compare>::Finalized()
{
	ClearAllElements();
}

template <class T, typename _Compare>
VOID GenericTable<T, _Compare>::Init()
{
	RtlInitializeGenericTable(&m_GenericTable, CompareRoutine, AllocateRoutine, FreeRoutine, nullptr);

	ExInitializeFastMutex(&m_FastMutex);
}


template <class T, typename _Compare>
GenericTable<T, _Compare>::GenericTable()
{
	Init();
}

template <class T, typename _Compare>
GenericTable<T, _Compare>::~GenericTable()
{
	Finalized();
}


