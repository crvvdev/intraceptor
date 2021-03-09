#pragma once

#include <windows.h>
#include <winternl.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#endif

#ifdef _WIN64
#pragma comment( lib, "libMinHook.x64.lib" )
#else
#pragma comment( lib, "libMinHook.x86.lib" )
#endif

#pragma comment( lib, "ntdll" )

#include "winstructs.hpp"
#include "commands.hpp"
#include "hooks.hpp"

#include "MinHook.h"