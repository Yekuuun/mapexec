/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : Base entry point for mapexec project.
 */

/**
 * Notes : 
 * 
 * Types
 * Resolver using hashing
 * Payload obfuscation
 * Custom injection using NT function (CreateFileMap & Mapviewoffile)
 */

#include "global.hpp"

int main(){
    DWORD ntdllHash = HashStringW(L"ntdll.dll");

    std::cout << "test:" << std::endl;
    std::cout << ntdllHash << std::endl;
    return 0;
}