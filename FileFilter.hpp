#pragma once
#include "GenericTable.hpp"
#include "Singleton.hpp"

constexpr ULONG FILE_PROTECT_TAG = 'mmPF';

struct ProtectFile
{
	WCHAR FilePath[MAX_PATH] = { 0 };
};

struct _CompareProtectFile
{
	RTL_GENERIC_COMPARE_RESULTS
		operator()(PVOID First, PVOID Second)
	{
		auto FirstData = reinterpret_cast<ProtectFile*>(First);
		auto SecondData = reinterpret_cast<ProtectFile*>(Second);

		RTL_GENERIC_COMPARE_RESULTS result = GenericEqual;
		
		UNICODE_STRING FirstDataStr;
		FirstDataStr.MaximumLength = FirstDataStr.Length = static_cast<USHORT>(wcslen(FirstData->FilePath) * sizeof(WCHAR));
		FirstDataStr.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, FirstDataStr.MaximumLength + sizeof(UNICODE_STRING), FILE_PROTECT_TAG));
		if (!FirstDataStr.Buffer)
		{
			return result;
		}
		RtlZeroMemory(FirstDataStr.Buffer, FirstDataStr.MaximumLength + sizeof(UNICODE_STRING));
		RtlCopyMemory(FirstDataStr.Buffer, FirstData->FilePath, FirstDataStr.MaximumLength);


		UNICODE_STRING SecondDataStr;
		SecondDataStr.MaximumLength = SecondDataStr.Length = static_cast<USHORT>(wcslen(SecondData->FilePath) * sizeof(WCHAR));
		SecondDataStr.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, SecondDataStr.MaximumLength + sizeof(UNICODE_STRING), FILE_PROTECT_TAG));
		if (!SecondDataStr.Buffer)
		{
			if (FirstDataStr.Buffer)
			{
				ExFreePoolWithTag(FirstDataStr.Buffer, FILE_PROTECT_TAG);
			}
			return result;
		}
		RtlZeroMemory(SecondDataStr.Buffer, SecondDataStr.MaximumLength + sizeof(UNICODE_STRING));
		RtlCopyMemory(SecondDataStr.Buffer, SecondData->FilePath, SecondDataStr.MaximumLength);

		if (FirstDataStr.Buffer && SecondDataStr.Buffer)
		{
			if (FsRtlIsNameInExpression(&SecondDataStr, &FirstDataStr, TRUE, NULL))
			{
				result = GenericEqual;
			}
			else
			{
				if (RtlCompareUnicodeString(&FirstDataStr, &SecondDataStr, TRUE) > 0)
				{
					result = GenericGreaterThan;
				}
				else if (RtlCompareUnicodeString(&FirstDataStr, &SecondDataStr, TRUE) < 0)
				{
					result = GenericLessThan;
				}
				else
				{
					result = GenericEqual;
				}
			}
		}

		if (FirstDataStr.Buffer)
		{
			ExFreePoolWithTag(FirstDataStr.Buffer, FILE_PROTECT_TAG);
		}
		if (SecondDataStr.Buffer)
		{
			ExFreePoolWithTag(SecondDataStr.Buffer, FILE_PROTECT_TAG);
		}

		return result;
	}

};

class FileFilter : public Singleton<FileFilter>
{
public:
	NTSTATUS IntializedFileFilter();
	NTSTATUS FinalizedFileFilter();

	NTSTATUS AddProtectFilePath(IN PWCHAR FilePath)
	{
		ProtectFile filePath{};
		RtlCopyMemory(filePath.FilePath, FilePath, wcslen(FilePath) * sizeof(WCHAR));

		return m_tableOfProtectFile->AddElement(filePath);
	}

	NTSTATUS DelProtectFilePath(IN PWCHAR FilePath)
	{
		ProtectFile filePath{};
		RtlCopyMemory(filePath.FilePath, FilePath, wcslen(FilePath) * sizeof(WCHAR));

		return m_tableOfProtectFile->DelElement(filePath);
	}

	BOOLEAN IsInTable(IN PUNICODE_STRING FilePath)
	{
		DbgBreakPoint();
		ProtectFile filePath{};
		RtlZeroMemory(&filePath, sizeof(filePath));
		if (FilePath->Length < MAX_PATH)
		{
			RtlCopyMemory(filePath.FilePath, FilePath->Buffer, FilePath->Length);
		}
		else
		{
			RtlCopyMemory(filePath.FilePath, FilePath->Buffer, MAX_PATH);
		}



		return m_tableOfProtectFile->IsInTable(filePath);
	}

private:
	GenericTable<ProtectFile, _CompareProtectFile>* m_tableOfProtectFile;
};