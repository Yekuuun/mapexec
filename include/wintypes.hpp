/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Contains base WIN API types definitions.
 */

#pragma once

#ifndef FALSE
#define FALSE                                       0
#endif

#ifndef TRUE
#define TRUE                                        1
#endif

//void 
typedef void  VOID;
typedef void* PVOID;
typedef void* LPVOID;
typedef void* HANDLE;
typedef void* HMODULE;

typedef HANDLE* PHANDLE;

//char & strings
typedef unsigned char  BYTE;
typedef unsigned char* PBYTE;

typedef char*       LPSTR;
typedef const char* LPCSTR;
typedef wchar_t     WCHAR;
typedef wchar_t*    LPCWCHAR;

typedef struct _UNICODE_STRING {
    unsigned short	length;
    unsigned short	maxLength;
    unsigned char	Reserved[4];
    wchar_t*	    buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//int
typedef int INT;
typedef unsigned int UINT;
typedef unsigned long long UINT64;

typedef long LONG;
typedef unsigned long  ULONG;
typedef unsigned long* PULONG;
typedef unsigned long long ULONGLONG;

typedef unsigned short  WORD;
typedef unsigned short* PWORD;
typedef unsigned long   DWORD;

typedef LONG KPRIORITY;
typedef LONG KPRIORITY, *PKPRIORITY;

//calls
#ifndef WINAPI
#define WINAPI __stdcall
#endif

#define NTAPI __stdcall