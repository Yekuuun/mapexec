/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Contains base implementation of GetModuleHandle & GetProcAddress function.
 */

#include "resolver.hpp"

/**
 * Get base address of PEB for current process
 */
static PVOID GetCurrentPebAddress(){
    return (PVOID)(__readgsqword(PEB_OFFSET));
}

/**
 * Custom GetModuleHandleW function 
 * @param LPCWTR => nameof dll. (ex : L"ntdll.dll")
 */
HANDLE GetModuleHandleW(DWORD dllHash){

    //ptr PEB.
    PPEB pPeb = (PPEB)(GetCurrentPebAddress());
    if(pPeb == NULL){
        return NULL;
    }

    //loaded modules.
    PPEB_LDR_DATA pPebLdrData = (PPEB_LDR_DATA)pPeb->Ldr;
    PLIST_ENTRY   pListEntry  = &pPebLdrData->InLoadOrderModuleList;

    //1th module.
    PLIST_ENTRY   moduleList  = pListEntry->Flink;


    return NULL;
}

/**
 * Custom GetProcAddress using Hash comparison
 * @param HANDLE => handle to module retrieved from GetModuleHandleW
 * @param DWORD  => function hash
 */
PVOID GetProcAddress(HANDLE hModule, DWORD Hash){
    return NULL;
}