#include "includes.hpp"

std::unique_ptr< CCommand > g_cmdDriver = nullptr;

DWORD WINAPI StartThread( PVOID )
{
	while ( !GetModuleHandleA( "ntdll.dll" ) )
		Sleep( 150 );

	MH_Initialize();

	g_cmdDriver = std::make_unique< CCommand >();

	if ( AttachConsole( GetCurrentProcessId() ) != ERROR_ACCESS_DENIED )
	{
		AllocConsole();
		FILE* f = nullptr;
		freopen_s( &f, "CONIN$", "r", stdin );
		freopen_s( &f, "CONOUT$", "w", stderr );
		freopen_s( &f, "CONOUT$", "w", stdout );
	}

	printf( "g_cmdDriver->Status: %d\n", g_cmdDriver->Status() );

	HMODULE ntdll = LoadLibraryA( "ntdll.dll" );

	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtClose" ) ), &hk_NtClose, reinterpret_cast< PVOID* >( &oNtClose ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtWaitForSingleObject" ) ), &hk_NtWaitForSingleObject, reinterpret_cast< PVOID* >( &oNtWaitForSingleObject ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtOpenProcess" ) ), &hk_NtOpenProcess, reinterpret_cast< PVOID* >( &oNtOpenProcess ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtReadVirtualMemory" ) ), &hk_NtReadVirtualMemory, reinterpret_cast< PVOID* >( &oNtReadVirtualMemory ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtWriteVirtualMemory" ) ), &hk_NtWriteVirtualMemory, reinterpret_cast< PVOID* >( &oNtWriteVirtualMemory ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtQueryVirtualMemory" ) ), &hk_NtQueryVirtualMemory, reinterpret_cast< PVOID* >( &oNtQueryVirtualMemory ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtAllocateVirtualMemory" ) ), &hk_NtAllocateVirtualMemory, reinterpret_cast< PVOID* >( &oNtAllocateVirtualMemory ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtFreeVirtualMemory" ) ), &hk_NtFreeVirtualMemory, reinterpret_cast< PVOID* >( &oNtFreeVirtualMemory ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtProtectVirtualMemory" ) ), &hk_NtProtectVirtualMemory, reinterpret_cast< PVOID* >( &oNtProtectVirtualMemory ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtQueryInformationProcess" ) ), &hk_NtQueryInformationProcess, reinterpret_cast< PVOID* >( &oNtQueryInformationProcess ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtSuspendProcess" ) ), &hk_NtSuspendProcess, reinterpret_cast< PVOID* >( &oNtSuspendProcess ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtResumeProcess" ) ), &hk_NtResumeProcess, reinterpret_cast< PVOID* >( &oNtResumeProcess ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtQuerySystemInformationEx" ) ), &hk_NtQuerySystemInformationEx, reinterpret_cast< PVOID* >( &oNtQuerySystemInformationEx ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtSetInformationProcess" ) ), &hk_NtSetInformationProcess, reinterpret_cast< PVOID* >( &oNtSetInformationProcess ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtFlushInstructionCache" ) ), &hk_NtFlushInstructionCache, reinterpret_cast< PVOID* >( &oNtFlushInstructionCache ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtFlushVirtualMemory" ) ), &hk_NtFlushVirtualMemory, reinterpret_cast< PVOID* >( &oNtFlushVirtualMemory ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtLockVirtualMemory" ) ), &hk_NtLockVirtualMemory, reinterpret_cast< PVOID* >( &oNtLockVirtualMemory ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtUnlockVirtualMemory" ) ), &hk_NtUnlockVirtualMemory, reinterpret_cast< PVOID* >( &oNtUnlockVirtualMemory ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtOpenThread" ) ), &hk_NtOpenThread, reinterpret_cast< PVOID* >( &oNtOpenThread ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtQueryInformationThread" ) ), &hk_NtQueryInformationThread, reinterpret_cast< PVOID* >( &oNtQueryInformationThread ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtSetInformationThread" ) ), &hk_NtSetInformationThread, reinterpret_cast< PVOID* >( &oNtSetInformationThread ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtGetContextThread" ) ), &hk_NtGetContextThread, reinterpret_cast< PVOID* >( &oNtGetContextThread ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtSetContextThread" ) ), &hk_NtSetContextThread, reinterpret_cast< PVOID* >( &oNtSetContextThread ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtSuspendThread" ) ), &hk_NtSuspendThread, reinterpret_cast< PVOID* >( &oNtSuspendThread ) );//
	MH_CreateHook( PVOID( GetProcAddress( ntdll, "NtResumeThread" ) ), &hk_NtResumeThread, reinterpret_cast< PVOID* >( &oNtResumeThread ) );//

	MH_EnableHook( MH_ALL_HOOKS );

	return EXIT_SUCCESS;
}

EXTERN_C __declspec( dllexport ) BOOL WINAPI DllMain( HMODULE hDll, DWORD dwReason, PVOID )
{
	if ( dwReason == DLL_PROCESS_ATTACH )
	{
		CreateThread( nullptr, NULL, StartThread, nullptr, NULL, nullptr );
	}
	return TRUE;
}