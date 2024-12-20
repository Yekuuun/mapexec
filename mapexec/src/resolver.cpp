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
 * Base check if string contains another.
 */
BOOL StringContains(wchar_t* haystack, wchar_t* needle){
    while(*haystack && (*haystack == *needle)){
        haystack++;
        needle++;
    }

    return (*haystack == *needle);
}

/**
 * Custom GetModuleHandleW function 
 * @param DWORD => hash.
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
    while(moduleList != pListEntry){
        PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)moduleList;
        DWORD currentFuncHash = HashStringW(pLdrDataEntry->BaseDllName.buffer);
        
        if(currentFuncHash == dllHash){
            return pLdrDataEntry->DllBase;
        }

        moduleList = moduleList->Flink;
    }

    return NULL;
}

/**
 * Custom GetProcAddress using Hash comparison
 * @param HANDLE => handle to module retrieved from GetModuleHandleW
 * @param DWORD  => function hash
 */
PVOID GetProcAddress(HANDLE hModule, DWORD Hash){
    BYTE* dllAddress = (BYTE*)hModule;

    PIMAGE_DOS_HEADER ptrDosHeader = (PIMAGE_DOS_HEADER)hModule;


    PIMAGE_NT_HEADERS64 ptrNtHeader = (PIMAGE_NT_HEADERS64)(dllAddress + ptrDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 ptrOptionnalHeader = &ptrNtHeader->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY ptrImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + ptrOptionnalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    //address of AddressOfNames
    auto rvaNames = (DWORD*)(dllAddress + ptrImageExportDirectory->AddressOfNames);
    auto rvaOrdinalsNames = (WORD*)(dllAddress + ptrImageExportDirectory->AddressOfNameOrdinals);
    auto rvaFunction = (DWORD*)(dllAddress + ptrImageExportDirectory->AddressOfFunctions);

    //looping through names exported
    for(int i = 0; i < ptrImageExportDirectory->NumberOfNames; i++)
    {
        char* functionName = (char*)(dllAddress + rvaNames[i]);
        DWORD funcHash     = HashStringA(functionName);

        if(funcHash == Hash){
            return (LPVOID)(dllAddress + rvaFunction[rvaOrdinalsNames[i]]);
        }
    }

    return nullptr;
}