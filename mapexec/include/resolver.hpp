#pragma once
#include "global.hpp"

/**
 * Custom GetModuleHandleW function 
 * @param DWORD => nameof dll (hashed). (ex : L"ntdll.dll") => hashed
 */
HANDLE GetModuleHandleW(DWORD);

/**
 * Custom GetProcAddress using Hash comparison
 * @param HANDLE => handle to module retrieved from GetModuleHandleW
 * @param DWORD  => function hash
 */
PVOID GetProcAddress(HANDLE, DWORD);