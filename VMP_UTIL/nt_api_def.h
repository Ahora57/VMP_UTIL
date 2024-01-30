#ifndef NTAPI_ENABLE
#include "struct.h"

NTSTATUS NTAPI NtQueryVirtualMemory
(
     HANDLE ProcessHandle,
     PVOID BaseAddress,
     MEMORY_INFORMATION_CLASS MemoryInformationClass,
     PVOID MemoryInformation,
     SIZE_T MemoryInformationLength,
     PSIZE_T ReturnLength
);

 
NTSTATUS NTAPI NtOpenSection
(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);


NTSTATUS NTAPI NtMapViewOfSection
(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
);

NTSTATUS
NTAPI
NtQuerySystemInformation
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID               SystemInformation,
	ULONG                SystemInformationLength,
	PULONG              ReturnLength OPTIONAL
);


NTSTATUS
NTAPI
NtSetInformationThread
(
	 HANDLE ThreadHandle,
	 THREADINFOCLASS ThreadInformationClass,
	 PVOID ThreadInformation,
	 ULONG ThreadInformationLength
);
NTSTATUS
NTAPI
NtQueryInformationThread
(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
);

NTSTATUS NTAPI NtClose
(
	HANDLE Handle
);

NTSTATUS NTAPI NtUnmapViewOfSection
(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
);


NTSTATUS NTAPI NtQueryInformationProcess
(
	 HANDLE ProcessHandle,
	 PROCESSINFOCLASS ProcessInformationClass,
	 PVOID ProcessInformation,
	 ULONG ProcessInformationLength,
	 PULONG ReturnLength
);

NTSTATUS NTAPI NtContinue
(
	PCONTEXT             ThreadContext,
	BOOLEAN              RaiseAlert
);

 


NTSTATUS NTAPI NtMapViewOfSection
(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID*			BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
);

NTSTATUS NTAPI NtUnmapViewOfSection
(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
);

NTSTATUS NTAPI LdrFindResource_U
(
	 PVOID DllHandle,
	 CONST LDR_RESOURCE_INFO* ResourceIdPath,
	 ULONG ResourceIdPathLength,
	 PIMAGE_RESOURCE_DATA_ENTRY* ResourceDataEntry
);

 

NTSTATUS NTAPI LdrAccessResource
(
	 PVOID DllHandle,
	 CONST PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry,
	 PVOID* Address,
	 PULONG Size
);

 
NTSTATUS NTAPI NtQueryObject
(
	HANDLE Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
);

PVOID  __cdecl VMP_Get_Import
(
    PVOID addr_mod,
    PVOID hash,
    BOOLEAN b
);
 
INT __cdecl VMP_STR_CMP
(
	CHAR* crypt_imp,
	CHAR* str,
	BOOLEAN b
);
#endif // !NTAPI_ENABLE
