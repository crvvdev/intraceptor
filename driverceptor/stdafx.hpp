#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#include "..\commands_id.hpp"
#include "kernel.hpp"
#include "tools.hpp"

#ifdef _DEBUG
#define DBGPRINT( s, ... ) DbgPrintEx( 0, 0, "[ Ceptor ] " s "\n", __VA_ARGS__ );
#else
#define DBGPRINT( s, ... ) ( s )
#endif

#include "helpers.hpp"
#include "handles.hpp"