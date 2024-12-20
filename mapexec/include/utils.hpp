/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Contains base utils functions.
 */

#pragma once
#include "global.hpp"

VOID PrintHexData(LPCSTR str, PBYTE payload, SIZE_T sPayload);

DWORD HashStringA(LPCSTR str);
DWORD HashStringW(LPCWSTR str);

VOID XorByInputKeys(PBYTE pShellcode, SIZE_T sShellcodeSize, PBYTE pKey, SIZE_T sKeySize);