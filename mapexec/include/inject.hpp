/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Injection chapter.
 */

#pragma once
#include "global.hpp"

BOOL RemoteMappingInjection(DWORD PID, PBYTE pPayload, SIZE_T sPayloadSize);
