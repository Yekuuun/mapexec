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
    
}

/**
 * Main injection function.
 * @param PID => given process ID.
 * @param pPayload => ptr to payload.
 * @param sPayloadSize => size of given payload.
 */
BOOL RemoteMappingInjection(DWORD PID, PBYTE pPayload, SIZE_T sPayloadSize){
    BOOL STATE = TRUE;

    return STATE;
}