/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Injection chapter.
 */

#include "inject.hpp"

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
    printf("[*] Successfully got handle to process with PID %lu \n", PID);
    printf("[*] PRESS <ENTER> to continue.... \n");
    getchar();

    return hProcess;
}

/**
 * Main injection function.
 * @param PID => given process ID.
 * @param pPayload => ptr to payload.
 * @param sPayloadSize => size of given payload.
 */
BOOL RemoteMappingInjection(DWORD PID, PBYTE pPayload, SIZE_T sPayloadSize){
    BOOL STATE      = TRUE;
    HANDLE hProcess = NULL;

    hProcess = GetGivenProcessHandle(PID);

    return STATE;
}