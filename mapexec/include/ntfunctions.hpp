/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Contains base ntfunctions declarations.
 */

#pragma once
#include "global.hpp"

typedef struct MEM_EXTENDED_PARAMETER {
    struct {
        DWORD64 Type : 8;    
        DWORD64 Reserved : 56; 
    } DUMMYSTRUCTNAME;
    union {
        DWORD64 ULong64;      
        PVOID Pointer;          
        SIZE_T Size;            
        HANDLE Handle;         
        DWORD ULong;            
    } DUMMYUNIONNAME;
} MEM_EXTENDED_PARAMETER, *PMEM_EXTENDED_PARAMETER;

typedef struct _PS_ATTRIBUTE {
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef union _LARGE_INTEGER {
  struct {
    DWORD LowPart;
    LONG  HighPart;
  } DUMMYSTRUCTNAME;
  struct {
    DWORD LowPart;
    LONG  HighPart;
  } u;
  LONGLONG QuadPart;
} LARGE_INTEGER;

typedef LARGE_INTEGER* PLARGE_INTEGER;

typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;                 
    void* lpSecurityDescriptor;   
    int   bInheritHandle;           
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

typedef void* PSECURITY_ATTRIBUTES;

// Définition de la convention d'appel NTAPI
#define NTAPI __stdcall

// NTOPENPROCESS
typedef NTSTATUS (NTAPI *PNTOPENPROCESS)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId 
);

// NTCREATETHREADEX
typedef NTSTATUS (NTAPI *PNTCREATETHREADEX)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);

// NTWAITFORSINGLEOBJECT
typedef NTSTATUS (NTAPI *PNTWAITFORSINGLEOBJECT)(
    HANDLE Handle,
    BOOL Alertable,
    PLARGE_INTEGER Timeout
);

// NTFREEVIRTUALMEMORY
typedef NTSTATUS (NTAPI *PNTFREEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

// NTCLOSE
typedef NTSTATUS (NTAPI *PNTCLOSE)(
    HANDLE Handle
);