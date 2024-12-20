/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Contains base utils functions.
 */

#pragma once
#include "global.hpp"

DWORD HashStringA(LPCSTR str);
DWORD HashStringW(LPCWSTR str);

PBYTE Ipv4Deobfuscation(const char* obfuscated_shellcode[], size_t shellcode_size);