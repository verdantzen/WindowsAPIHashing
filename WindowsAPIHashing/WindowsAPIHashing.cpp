#include <Windows.h>
#include <iostream>

using namespace std;

using prototypeLoadLibraryA = HMODULE(WINAPI*)(_In_ LPCSTR lpLibFileName);
using prototypeMessageBoxA = int(WINAPI*)(
	_In_ HWND   hWnd,
	_In_ LPCSTR lpText,
	_In_ LPCSTR lpCaption,
	_In_           UINT   uType
	);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	//PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	//PPEBLOCKROUTINE         FastPebLockRoutine;
	//PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	//PPVOID                  KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	//PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	//PPVOID                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	//LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	//PPVOID* ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;

DWORD REVilCustomHashModule(PWSTR moduleName) {
	DWORD s = 0x3b;
	for (DWORD i = 0; i < wcslen(moduleName); i++)
	{
		s = moduleName[i] + 0x10f * s;
	}
	return s & 0x1fffff;
}


DWORD REVilCustomHashFunction(PSTR moduleName) {
	DWORD s = 0x3b;
	for (DWORD i = 0; i < strlen(moduleName); i++)
	{
		s = moduleName[i] + 0x10f * s;
	}
	return s & 0x1fffff;
}

PVOID fnFindModuleAdrr(DWORD hashCompare) {
	// b1: Từ thằng TEB ta trỏ đến thằng PEB
	PPEB myPEB = (PPEB)__readfsdword(0x30); // fs[0x30] trong x86 --> PEB - Process Environment Block

	// b2: PEB point to LoaderData (Ldr), LoaderData có kiểu dữ liệu là PEB_LDR_DATA
	PPEB_LDR_DATA Ldr = (PPEB_LDR_DATA)myPEB->LoaderData;

	// b3: LoaderData trỏ đến InLoadOrderModuleList ,ta đặt tên cho nó là moduleList có kiểu dữ liệu là LDR_MOUDLE
	PLDR_MODULE moduleList = (PLDR_MODULE)Ldr->InLoadOrderModuleList.Flink;

	// b4: Hiển thị tên moudle
	PWSTR baseDLLName = moduleList->BaseDllName.Buffer;
	PWSTR firstDLLName = moduleList->BaseDllName.Buffer;

	// b5: ta trỏ từ moudleList này đến moduleList khác, mục đích của việc này đó là ta trỏ từ module này đến moudle tiếp theo
	do {
		moduleList = (PLDR_MODULE)moduleList->InLoadOrderModuleList.Flink;

		// Hiển thị tên module.
		baseDLLName = moduleList->BaseDllName.Buffer;

		// in ra màn hình
		wcout << baseDLLName << std::endl;

		if (REVilCustomHashModule(baseDLLName) == hashCompare) {
			return moduleList->BaseAddress;
		}
	} while (firstDLLName != baseDLLName);
}

PDWORD fnResolveAPIFromHash(DWORD hashMoudle, DWORD hashFunction) {
	HMODULE moduleEntry = NULL;
	PDWORD functionAddr = (PDWORD)0;
	moduleEntry = (HMODULE)fnFindModuleAdrr(hashMoudle); // 0x12af9d: kernel32.dll

	// find dosHeader and ntHeaders
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleEntry;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)dosHeader + dosHeader->e_lfanew);

	// Find dataDirectory ->> IMAGE_DIRECTORY_ENTRY_EXPORT
	PIMAGE_DATA_DIRECTORY dataDirectory = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// Find exportDirectory
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)moduleEntry + dataDirectory->VirtualAddress);

	// liet ke cac thong tin duoi day
	DWORD numberOfNames = exportDirectory->NumberOfNames;
	PDWORD AddressOfFunctionsRVA = (PDWORD)((DWORD_PTR)moduleEntry + exportDirectory->AddressOfFunctions);
	PDWORD AddressOfNamesRVA = (PDWORD)((DWORD_PTR)moduleEntry + exportDirectory->AddressOfNames);
	PWORD AddressOfNameOrdinalsRVa = (PWORD)((DWORD_PTR)moduleEntry + exportDirectory->AddressOfNameOrdinals);

	// lay danh sach cac ham va tim kiem ham theo hash
	for (DWORD i = 0; i < numberOfNames; i++)
	{
		PSTR functionName = (PSTR)((DWORD_PTR)moduleEntry + AddressOfNamesRVA[i]);
		wcout << functionName << std::endl;
		if (REVilCustomHashFunction(functionName) == hashFunction) {

			WORD ordinal = AddressOfNameOrdinalsRVa[i];
			functionAddr = (PDWORD)((DWORD_PTR)moduleEntry + AddressOfFunctionsRVA[ordinal]);
			return functionAddr;
		}
	}
}

int main() {
	// 0x12af9d : KERNEL32.DLL
	// 0x5ed17	: LoadLibraryA
	prototypeLoadLibraryA pLoadLibraryA = (prototypeLoadLibraryA)fnResolveAPIFromHash(0x12af9d, 0x5ed17);
	pLoadLibraryA("USER32.DLL");
	DWORD hashMsgBoxA = REVilCustomHashFunction((PSTR)"MessageBoxA");
	DWORD hashUser32 = REVilCustomHashFunction((PSTR)"USER32.DLL");
	prototypeMessageBoxA pMessageBoxA = (prototypeMessageBoxA)fnResolveAPIFromHash(hashUser32, hashMsgBoxA);
	pMessageBoxA(NULL, "testing testing testing!", "testing", MB_OK);
	return 0;
}