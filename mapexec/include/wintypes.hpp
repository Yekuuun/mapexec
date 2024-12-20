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

typedef bool BOOL;

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
typedef char  CHAR;
typedef char* PCHAR;
typedef char* CSTR;
typedef CSTR* PCSTR;

typedef char*       LPSTR;
typedef const char* LPCSTR;
typedef wchar_t     WCHAR;
typedef wchar_t*    LPCWSTR;

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
typedef size_t SIZE_T;
typedef size_t* PSIZE_T;

typedef long LONG;
typedef unsigned long  ULONG;
typedef unsigned long* PULONG;
typedef unsigned long long ULONGLONG;
typedef long long LONGLONG;
typedef long NTSTATUS;

typedef unsigned short  WORD;
typedef unsigned short* PWORD;
typedef unsigned long   DWORD;

typedef LONG KPRIORITY;
typedef LONG KPRIORITY, *PKPRIORITY;
typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;

//calls
#ifndef WINAPI
#define WINAPI __stdcall
#endif

#define NTAPI __stdcall

#ifdef _WIN64
#define TIB_OFFSET 0x30
#else
#define TIB_OFFSET 0x18
#endif

#ifdef _WIN64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

extern "C" unsigned __int64 __readgsqword(unsigned long Offset);

//------

#define STANDARD_RIGHTS_REQUIRED  0x000F0000
#define SYNCHRONIZE               0x00100000

#define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
