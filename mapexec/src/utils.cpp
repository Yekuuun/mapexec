/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Contains base utils functions.
 */


#include "utils.hpp"

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
