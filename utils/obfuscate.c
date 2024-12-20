/**
 * This folder contains base utils & needs for mapexec (samples I made for mapexec implementation.)
 */

#include <stdio.h>
#include <windows.h>

//https://github.com/arsium/ShellCodeExec/blob/main/ShellCodeLoader.c
char shellcode_x64[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

//Generated with obfucate function below.
const char* obfuscated_shellcode_x64[] = {
    "72.131.236.40", "72.131.228.240", "72.141.21.102", "0.0.0.72",
    "141.13.82.0", "0.0.232.158", "0.0.0.76", "139.248.72.141",
    "13.93.0.0", "0.255.208.72", "141.21.95.0", "0.0.72.141",
    "13.77.0.0", "0.232.127.0", "0.0.77.51", "201.76.141.5",
    "97.0.0.0", "72.141.21.78", "0.0.0.72", "51.201.255.208",
    "72.141.21.86", "0.0.0.72", "141.13.10.0", "0.0.232.86",
    "0.0.0.72", "51.201.255.208", "75.69.82.78", "69.76.51.50",
    "46.68.76.76", "0.76.111.97", "100.76.105.98", "114.97.114.121",
    "65.0.85.83", "69.82.51.50", "46.68.76.76", "0.77.101.115",
    "115.97.103.101", "66.111.120.65", "0.72.101.108", "108.111.32.119",
    "111.114.108.100", "0.77.101.115", "115.97.103.101", "0.69.120.105",
    "116.80.114.111", "99.101.115.115", "0.72.131.236", "40.101.76.139",
    "4.37.96.0", "0.0.77.139", "64.24.77.141", "96.16.77.139",
    "4.36.252.73", "139.120.96.72", "139.241.172.132", "192.116.38.138",
    "39.128.252.97", "124.3.128.236", "32.58.224.117", "8.72.255.199",
    "72.255.199.235", "229.77.139.0", "77.59.196.117", "214.72.51.192",
    "233.167.0.0", "0.73.139.88", "48.68.139.75", "60.76.3.203",
    "73.129.193.136", "0.0.0.69", "139.41.77.133", "237.117.8.72",
    "51.192.233.133", "0.0.0.78", "141.4.43.69", "139.113.4.77",
    "3.245.65.139", "72.24.69.139", "80.32.76.3", "211.255.201.77",
    "141.12.138.65", "139.57.72.3", "251.72.139.242", "166.117.8.138",
    "6.132.192.116", "9.235.245.226", "230.72.51.192", "235.78.69.139",
    "72.36.76.3", "203.102.65.139", "12.73.69.139", "72.28.76.3",
    "203.65.139.4", "137.73.59.197", "124.47.73.59", "198.115.42.72",
    "141.52.24.72", "141.124.36.48", "76.139.231.164", "128.62.46.117",
    "250.164.199.7", "68.76.76.0", "73.139.204.65", "255.215.73.139",
    "204.72.139.214", "233.20.255.255", "255.72.3.195", "72.131.196.40",
    "195.0.0.0"
};


//-------------------------------IPV4 OBFUSCATION-----------------------------------------
/**
 * Generate IPv4 format address.
 */
static char* GenerateIpv4(int a, int b, int c, int d) {
    static char Output[32];

    snprintf(Output, sizeof(Output), "%d.%d.%d.%d", a, b, c, d);
    return Output;
}

/**
 * Generate the ipv4 shellcode obfuscation format.
 */
BOOL GenerateIpv4ObfuscationWithPadding(unsigned char *pShellcode, SIZE_T sShellcodeSize) {
    if (pShellcode == NULL || sShellcodeSize == 0) {
        return FALSE;
    }

    // Calculer la taille finale avec padding
    SIZE_T paddedSize = (sShellcodeSize % 4 == 0) ? sShellcodeSize : (sShellcodeSize + (4 - (sShellcodeSize % 4)));
    unsigned char* paddedShellcode = (unsigned char*)malloc(paddedSize);
    if (paddedShellcode == NULL) {
        return FALSE;
    }

    // padding management.
    memcpy(paddedShellcode, pShellcode, sShellcodeSize);
    memset(paddedShellcode + sShellcodeSize, 0x00, paddedSize - sShellcodeSize); // Padding with 0x00

    printf("unsigned char obfuscatedIP[] = {\n\t");

    for (SIZE_T i = 0; i < paddedSize; i += 4) {
        char* IP = GenerateIpv4(
            paddedShellcode[i],
            paddedShellcode[i + 1],
            paddedShellcode[i + 2],
            paddedShellcode[i + 3]
        );

        if (i == paddedSize - 4) {
            printf("\"%s\"", IP);
        } else {
            printf("\"%s\", ", IP);
        }

        if ((i + 4) % 16 == 0) {
            printf("\n\t");
        }
    }

    printf("\n};\n\n");

    free(paddedShellcode);
    return TRUE;
}
/**
 * Function declaration.
 */
typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(
    PCSTR       S,
    BOOLEAN     Strict,
    PCSTR*      Terminator,
    PVOID       Addr
);

/**
 * Deobfuscating payload.
 */
BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize, IN SIZE_T OriginalSize) {
    PBYTE pBuffer = NULL, TmpBuffer = NULL;
    SIZE_T sBuffSize = NULL;
    PCSTR Terminator = NULL;
    NTSTATUS STATUS = NULL;

    fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlIpv4StringToAddressA");
    if (pRtlIpv4StringToAddressA == NULL) {
        return FALSE;
    }

    sBuffSize = NmbrOfElements * 4;
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    TmpBuffer = pBuffer;

    for (int i = 0; i < NmbrOfElements; i++) {
        if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
            printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], STATUS);
            HeapFree(GetProcessHeap(), 0, pBuffer);
            return FALSE;
        }

        TmpBuffer = (PBYTE)(TmpBuffer + 4);
    }

    //Remove padding.
    *ppDAddress = (PBYTE)HeapAlloc(GetProcessHeap(), 0, OriginalSize);
    if (*ppDAddress == NULL) {
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return FALSE;
    }

    memcpy(*ppDAddress, pBuffer, OriginalSize); // Copier uniquement la taille originale
    *pDSize = OriginalSize;

    return TRUE;
}

SIZE_T CountElements(const char* array[]) {
    size_t count = 0;
    while (array[count] != NULL) {
        count++;
    }
    return count;
}


int main(){
    //OBFUSCATE.
    // if (!GenerateIpv4ObfuscationWithPadding(shellcode_x64, sizeof(shellcode_x64))) {
    //     fprintf(stderr, "Erreur : Taille du shellcode invalide\n");
    //     return -1;
    // }

    // printf("[#] Press <Enter> To Quit ... ");
    // getchar();

    //DEOBFUSCATE
    // PBYTE	pDAddress	= NULL;
	// SIZE_T	sDSize		= NULL;

    // SIZE_T  NumberOfElements = CountElements(obfuscated_shellcode_x64);

	// if (!Ipv4Deobfuscation(obfuscated_shellcode_x64, NumberOfElements, &pDAddress, &sDSize, sizeof(shellcode_x64))){
	// 	return -1;
	// }

	// printf("[+] Deobfuscated Bytes at 0x%p of Size %ld ::: \n", pDAddress, sDSize);
	// for (size_t i = 0; i < sDSize; i++){
	// 	if (i % 16 == 0)
	// 		printf("\n\t");

	// 	printf("%0.2X ", pDAddress[i]);
	// }

	// HeapFree(GetProcessHeap(), 0, pDAddress);

	// printf("\n\n[#] Press <Enter> To Quit ... ");
	// getchar();
    
    return EXIT_SUCCESS;
}