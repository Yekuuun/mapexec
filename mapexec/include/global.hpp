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
#define NTDLL_HASH 817310536
#define NTOPEN_PROCESS_HASH 3750040962