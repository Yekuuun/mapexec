/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Contains global config.
 */

#pragma once

#include <iostream>         //BASE.
#include <cstdint>

#include "wintypes.hpp"     //WIN API TYPES.
#include "pe.hpp"           //PE.
#include "status.hpp"       //NT_STATUS TYPES.
#include "ntfunctions.hpp"  //NT FUNCTIONS.

#include "utils.hpp"        //UTILS FUNCTIONS.
#include "resolver.hpp"     //RESOLVER FUNCTIONS.
#include "inject.hpp"       //INJECTION.

//-------------GLOBAL VARIABLES------------------

//hash => generated from HashStringW & HashStringA
#define NTDLL_HASH            817310536
#define KERNEL32_HASH         356045008
#define KERNEL_BASE           4152772134
#define NTOPEN_PROCESS_HASH   3808979763
#define NTCLOSE_HASH          2278454744
#define CREATEFILEMAPPINGA    2493032513
#define MAPVIEWOFFILE3        1095683457
#define MAPVIEWOFFILE         2766363534
#define NTCREATETHREADEX_HASH 222339627
#define NTWAITSINGLEOBJECT    3975224343