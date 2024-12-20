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

/**
 * ENTRY POINT.
 */
int main(int argc, char *argv[]){
    if(argc != 2){
        printf("[!] ERROR : must pass <PID> in param... \n");
        return EXIT_FAILURE;
    }

    DWORD PID = atoi(argv[1]);

    return EXIT_SUCCESS;
}