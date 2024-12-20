/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Contains base utils functions.
 */


#include "utils.hpp"

/**
 * Printing HEX data properly.
 */
VOID PrintHexData(LPCSTR str, PBYTE payload, SIZE_T sPayload){
    printf("unsigned char %s[]{", str);

    for(int i = 0; i < sPayload; i++){
        if(i % 16 == 0){
            printf("\n\t");
        }

        if(i < sPayload - 1){
            printf("0x%02X, ", payload[i]);
        }
        else{
            printf("0x%02X ", payload[i]);
        }
    }

    printf("\n");
}

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


/**
 * XOR using input keys.
 */
VOID XorByInputKeys(PBYTE pShellcode, SIZE_T sShellcodeSize, PBYTE pKey, SIZE_T sKeySize){
    for(size_t i = 0, j = 0; i < sShellcodeSize; i++){
        pShellcode[i] ^= pKey[i % sKeySize];
    }
}