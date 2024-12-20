/**
 * This folder contains base utils & needs for mapexec (samples I made for mapexec implementation.)
 */

#include <stdio.h>
#include <windows.h>

//----------------STRING HASHING--------------------
static DWORD HashStringA(LPCSTR str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash << 5) + hash + *str++;
    }
    return hash;
}

static DWORD HashStringW(LPCWSTR str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash << 5) + hash + (*str++ & 0xFF);
    }
    return hash;
}

//used to get HASH of functions in map exec.
int main(int argc, char *argv[]){
    printf("hash : %lu\n", HashStringA(argv[1]));
    // printf("KERNEL 32 : %lu", HashStringW(L"KERNEL32.DLL"));
    // printf("KERNEL base : %lu", HashStringW(L"KERNELBASE.dll"));
    return EXIT_SUCCESS;
}