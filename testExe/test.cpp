#include <Windows.h>
#include <cstdio>
#include <winternl.h>
#include <cstdint>
#include <TlHelp32.h>

#pragma comment( lib, "ntdll" )

#define CEPTOR_VALID_HANDLE( h )	( ( ( ( std::uint64_t )h >> 20 ) & 0xFFF ) == 0xF0F )

DWORD FindProcess( const wchar_t* szName )
{
	HANDLE hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if ( !hSnap )
		return 0;

	DWORD ProcessId = NULL;

	PROCESSENTRY32 pe32{ };
	pe32.dwSize = sizeof( pe32 );

	Process32First( hSnap, &pe32 );
	do
	{
		if ( !wcscmp( pe32.szExeFile, szName ) )
		{
			ProcessId = pe32.th32ProcessID;
			break;
		}
	} while ( Process32Next( hSnap, &pe32 ) );

	return ProcessId;
}

DWORD WINAPI Worker( PVOID )
{
	while ( true )
	{
		Sleep( 60 * 1000 );
		printf( "Thread finished\n" );
		ExitThread( 0 );
	}
	return 0;
}

int main()
{
	auto hModule = LoadLibraryA( "intraceptor.dll" );
	if ( !hModule )
	{
		printf( "LoadLibrary returned %d\n", GetLastError() );
		getchar();
		return 1;
	}

	Sleep( 2500 );

	printf( "Trying to attach into explorer.exe\n" );
	ULONG ExplorerPID = FindProcess( L"explorer.exe" );
	printf( "Explorer PID: 0x%X\n", ExplorerPID );

	HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, ExplorerPID );
	if ( hProcess )
	{
		printf( "Process Handle: 0x%p\n", hProcess );

		//
		// NtQueryInformationProcess
		//
		PROCESS_BASIC_INFORMATION pbi{ };
		DWORD pbiLen = 0;
		NtQueryInformationProcess( hProcess, PROCESSINFOCLASS::ProcessBasicInformation, &pbi, sizeof( pbi ), &pbiLen );

		printf( "PEB: 0x%p\n", pbi.PebBaseAddress );

		//
		// VirtualAllocEx
		//
		auto Addr = VirtualAllocEx( hProcess, nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
		printf( "Addr: 0x%p\n", Addr );

		//
		// RPM
		//
		ULONG AddrVal = 10;
		ReadProcessMemory( hProcess, Addr, &AddrVal, sizeof( AddrVal ), nullptr );

		printf( "Addr: 0x%X\n", AddrVal );

		//
		// WPM
		//
		if ( WriteProcessMemory( hProcess, Addr, "\xAD\xED\xEF", 4, nullptr ) )
			printf( "Write success!\n" );

		//
		// RPM 2
		//
		ReadProcessMemory( hProcess, Addr, &AddrVal, sizeof( AddrVal ), nullptr );

		printf( "Addr: 0x%X\n", AddrVal );

		//
		// VirtualProtectEx
		//
		DWORD dwOld = 0;
		VirtualProtectEx( hProcess, Addr, 0x1000, PAGE_EXECUTE_READWRITE, &dwOld );

		//
		// VirtualQueryEx
		//
		MEMORY_BASIC_INFORMATION mbi{ };
		if ( VirtualQueryEx( hProcess, Addr, &mbi, sizeof( mbi ) ) )
			printf( "AllocationBase: 0x%p\n", mbi.AllocationBase );
		
		//
		// VirtualFreeEx
		//
		VirtualFreeEx( hProcess, Addr, 0, MEM_RELEASE );

		//
		// CreateThread
		//
		DWORD ThreadId = 0;
		CreateThread( nullptr, NULL, Worker, nullptr, NULL, &ThreadId );
		printf( "ThreadId: %d\n", ThreadId );

		//
		// OpenThread
		//
		HANDLE hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, ThreadId );
		if ( hThread )
		{
			printf( "Thread Handle: 0x%p\n", hThread );

			CONTEXT ctx{ };
			ctx.ContextFlags = CONTEXT_ALL;

			SuspendThread( hThread );
			GetThreadContext( hThread, &ctx );
			printf( "Rip = 0x%llX\n", ctx.Rip );
			SetThreadContext( hThread, &ctx );
			ResumeThread( hThread );

			auto Res = WaitForSingleObject( hThread, INFINITE );
			printf( "WaitForSingleObject res: %d\n", Res );

			CloseHandle( hThread );
		}

		CloseHandle( hProcess );
	}

	Sleep( INFINITE );
	return 0;
}