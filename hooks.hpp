#pragma once

//
// CloseHandle
//
NTSTATUS( NTAPI* oNtClose )( HANDLE );

NTSTATUS NTAPI hk_NtClose( HANDLE Handle )
{
	if ( CEPTOR_VALID_HANDLE( Handle ) && g_cmdDriver->DetachProcess( uint64_t( Handle ) ) )
	{
		printf( "[ ! ] NtClose - closed handle = 0x%llX\n", uint64_t( Handle ) );
		return STATUS_SUCCESS;
	}

	return oNtClose( Handle );
}

//
// OpenProcess
//
NTSTATUS( NTAPI* oNtOpenProcess )( PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID* );

NTSTATUS NTAPI hk_NtOpenProcess( PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId )
{
	if ( ProcessHandle && ClientId && ClientId->UniqueProcess != ULongToHandle( GetCurrentProcessId() ) )
	{
		uint64_t Handle = NULL;
		if ( g_cmdDriver->AttachProcess( uint64_t( ClientId->UniqueProcess ), uint64_t( ClientId->UniqueThread ), &Handle ) )
		{
			*ProcessHandle = PHANDLE( Handle );
			printf( "[ ! ] NtOpenProcess on TID: 0x%p, PID: 0x%p - opened handle = 0x%p\n", ClientId->UniqueThread, ClientId->UniqueProcess, *ProcessHandle );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtOpenProcess - TID: 0x%p, PID: 0x%p - returned 0x%X\n", ClientId->UniqueThread, ClientId->UniqueProcess, g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtOpenProcess( ProcessHandle, DesiredAccess, ObjectAttributes, ClientId );
}

//
// ReadProcessMemory
//
NTSTATUS( NTAPI* oNtReadVirtualMemory )( HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T );

NTSTATUS NTAPI hk_NtReadVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesReaded )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) )
	{
		if ( g_cmdDriver->ReadProcessMemory(
			uint64_t( ProcessHandle ),
			reinterpret_cast< uint64_t* >( BaseAddress ),
			reinterpret_cast< uint64_t* >( Buffer ),
			NumberOfBytesToRead,
			NumberOfBytesReaded )
			)
		{
			//	printf( "[ ! ] NtReadVirtualMemory - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtReadVirtualMemory returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtReadVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded );
}

//
// WriteProcessMemory
//
NTSTATUS( NTAPI* oNtWriteVirtualMemory )( HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T );

NTSTATUS NTAPI hk_NtWriteVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) )
	{
		if ( g_cmdDriver->WriteProcessMemory(
			uint64_t( ProcessHandle ),
			reinterpret_cast< uint64_t* >( BaseAddress ),
			reinterpret_cast< uint64_t* >( Buffer ),
			NumberOfBytesToWrite,
			NumberOfBytesWritten )
			)
		{
			//	printf( "[ ! ] NtWriteVirtualMemory - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtWriteVirtualMemory returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten );
}

//
// VirtualQueryEx
//
NTSTATUS( NTAPI* oNtQueryVirtualMemory )( HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T );

NTSTATUS NTAPI hk_NtQueryVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, SIZE_T Length, PSIZE_T ResultLength )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) )
	{
		if ( g_cmdDriver->VirtualQueryEx(
			uint64_t( ProcessHandle ),
			reinterpret_cast< uint64_t* >( BaseAddress ),
			MemoryInformationClass,
			reinterpret_cast< uint64_t* >( Buffer ),
			Length,
			reinterpret_cast< uint32_t* >( ResultLength ) )
			)
		{
			//	printf( "[ ! ] NtQueryVirtualMemory - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtQueryVirtualMemory returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtQueryVirtualMemory( ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength );
}

//
// VirtualAllocEx
//
NTSTATUS( NTAPI* oNtAllocateVirtualMemory )( HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG );

NTSTATUS NTAPI hk_NtAllocateVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) && BaseAddress && RegionSize )
	{
		std::uint64_t AllocBase = g_cmdDriver->VirtualAllocEx(
			uint64_t( ProcessHandle ),
			std::uint64_t( *BaseAddress ),
			*RegionSize,
			AllocationType,
			Protect
		);

		if ( AllocBase )
		{
			*BaseAddress = PVOID( AllocBase );
			//	printf( "[ ! ] NtAllocateVirtualMemory - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtAllocateVirtualMemory returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect );
}

//
// VirtualFreeEx
//
NTSTATUS( NTAPI* oNtFreeVirtualMemory )( HANDLE, PVOID*, PSIZE_T, ULONG );

NTSTATUS NTAPI hk_NtFreeVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) && BaseAddress && RegionSize )
	{
		if ( g_cmdDriver->VirtualFreeEx(
			uint64_t( ProcessHandle ),
			reinterpret_cast< std::uint64_t* >( *BaseAddress ),
			*RegionSize,
			FreeType )
			)
		{
			//	printf( "[ ! ] NtFreeVirtualMemory - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtFreeVirtualMemory returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtFreeVirtualMemory( ProcessHandle, BaseAddress, RegionSize, FreeType );
}

//
// VirtualProtectEx
// 
NTSTATUS( NTAPI* oNtProtectVirtualMemory )( HANDLE, PVOID*, PSIZE_T, ULONG, PULONG );

NTSTATUS NTAPI hk_NtProtectVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) && BaseAddress && NumberOfBytesToProtect )
	{
		std::uint32_t OldAccess{ };

		if ( g_cmdDriver->VirtualProtectEx(
			uint64_t( ProcessHandle ),
			reinterpret_cast< std::uint64_t* >( *BaseAddress ),
			*NumberOfBytesToProtect,
			NewAccessProtection,
			&OldAccess )
			)
		{
			if ( OldAccessProtection )
				*OldAccessProtection = OldAccess;

			//	printf( "[ ! ] NtProtectVirtualMemory - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtProtectVirtualMemory returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtProtectVirtualMemory( ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection );
}

//
// VirtualLockEx
//
NTSTATUS( NTAPI* oNtLockVirtualMemory )( HANDLE, PVOID*, PSIZE_T, ULONG );

NTSTATUS NTAPI hk_NtLockVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG LockOption )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) && BaseAddress && RegionSize )
	{
		if ( g_cmdDriver->VirtualLockEx(
			uint64_t( ProcessHandle ),
			reinterpret_cast< std::uint64_t* >( *BaseAddress ),
			*RegionSize,
			LockOption )
			)
		{
			//	printf( "[ ! ] NtLockVirtualMemory - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtLockVirtualMemory returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtLockVirtualMemory( ProcessHandle, BaseAddress, RegionSize, LockOption );
}

//
// VirtualUnlockEx
//
NTSTATUS( NTAPI* oNtUnlockVirtualMemory )( HANDLE, PVOID*, PSIZE_T, ULONG );

NTSTATUS NTAPI hk_NtUnlockVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG LockOption )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) && BaseAddress && RegionSize )
	{
		if ( g_cmdDriver->VirtualUnlockEx(
			uint64_t( ProcessHandle ),
			reinterpret_cast< std::uint64_t* >( *BaseAddress ),
			*RegionSize,
			LockOption )
			)
		{
			//	printf( "[ ! ] NtUnlockVirtualMemory - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtUnlockVirtualMemory returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtUnlockVirtualMemory( ProcessHandle, BaseAddress, RegionSize, LockOption );
}

//
// FlushInstructionCache
//
NTSTATUS( NTAPI* oNtFlushInstructionCache )( HANDLE, PVOID, ULONG );

NTSTATUS NTAPI hk_NtFlushInstructionCache( HANDLE processHandle, PVOID baseAddress, ULONG numberOfBytesToFlush )
{
	if ( processHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( processHandle ) && baseAddress )
	{
		if ( g_cmdDriver->FlushInstructionCache(
			uint64_t( processHandle ),
			reinterpret_cast< std::uint64_t* >( baseAddress ),
			numberOfBytesToFlush )
			)
		{
			//	printf( "[ ! ] NtFlushInstructionCache - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtFlushInstructionCache returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtFlushInstructionCache( processHandle, baseAddress, numberOfBytesToFlush );
}

//
// NtSetInformationProcess
//
NTSTATUS( NTAPI* oNtSetInformationProcess )( HANDLE, PROCESSINFOCLASS, PVOID, ULONG );

NTSTATUS NTAPI hk_NtSetInformationProcess( HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) && ProcessInformation && ProcessInformationLength > 0 )
	{
		if ( g_cmdDriver->SetInformationProcess(
			uint64_t( ProcessHandle ),
			ProcessInformationClass,
			reinterpret_cast< std::uint64_t* >( ProcessInformation ),
			ProcessInformationLength )
			)
		{
			//	printf( "[ ! ] NtSetInformationProcess - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtSetInformationProcess returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtSetInformationProcess( ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength );
}

//
// NtFlushVirtualMemory
//
NTSTATUS( NTAPI* oNtFlushVirtualMemory )( HANDLE, PVOID*, PSIZE_T, PIO_STATUS_BLOCK );

NTSTATUS NTAPI hk_NtFlushVirtualMemory( HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, PIO_STATUS_BLOCK ioStatus )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) && BaseAddress && RegionSize && ioStatus )
	{
		if ( g_cmdDriver->FlushMemory(
			uint64_t( ProcessHandle ),
			reinterpret_cast< std::uint64_t* >( *BaseAddress ),
			*RegionSize,
			ioStatus )
			)
		{
			//	printf( "[ ! ] NtFlushVirtualMemory - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtFlushVirtualMemory returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtFlushVirtualMemory( ProcessHandle, BaseAddress, RegionSize, ioStatus );
}

//
// SuspendProcess
//
NTSTATUS( NTAPI* oNtSuspendProcess )( HANDLE );

NTSTATUS NTAPI hk_NtSuspendProcess( HANDLE ProcessHandle )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) )
	{
		if ( g_cmdDriver->SuspendProcess( uint64_t( ProcessHandle ) ) )
		{
			//printf( "[ ! ] NtSuspendProcess - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtSuspendProcess returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtSuspendProcess( ProcessHandle );
}

//
// ResumeProcess
//
NTSTATUS( NTAPI* oNtResumeProcess )( HANDLE );

NTSTATUS NTAPI hk_NtResumeProcess( HANDLE ProcessHandle )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) )
	{
		if ( g_cmdDriver->ResumeProcess( uint64_t( ProcessHandle ) ) )
		{
			//	printf( "[ ! ] NtResumeProcess - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtResumeProcess returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtResumeProcess( ProcessHandle );
}

NTSTATUS( NTAPI* oNtOpenThread )( PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID* );

NTSTATUS NTAPI hk_NtOpenThread( PHANDLE threadHandle, ACCESS_MASK accessMask, POBJECT_ATTRIBUTES objectAttributes, CLIENT_ID* clientId )
{
	if ( threadHandle &&
		clientId &&
		clientId->UniqueThread != ULongToHandle( GetCurrentThreadId() ) &&
		clientId->UniqueProcess != GetCurrentProcess() )
	{
		std::uint64_t OutThreadHandle{ };

		if ( g_cmdDriver->OpenThread(
			uint64_t( clientId->UniqueThread ),
			uint64_t( clientId->UniqueProcess ),
			&OutThreadHandle )
			)
		{
			*threadHandle = PHANDLE( OutThreadHandle );
			printf( "[ ! ] NtOpenThread on TID: 0x%p - opened handle = 0x%p\n", clientId->UniqueThread, *threadHandle );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtOpenThread ( Thread = 0x%p, Process = 0x%p ) returned 0x%X\n", clientId->UniqueThread, clientId->UniqueProcess, g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtOpenThread( threadHandle, accessMask, objectAttributes, clientId );
}

NTSTATUS( NTAPI* oNtQueryInformationThread )( HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG );

NTSTATUS NTAPI hk_NtQueryInformationThread( HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength, PULONG returnLength )
{
	if ( threadHandle != GetCurrentThread() && CEPTOR_VALID_HANDLE( threadHandle ) )
	{
		std::uint32_t ReturnLen = NULL;

		if ( g_cmdDriver->QueryThreadInformation(
			uint64_t( threadHandle ),
			threadInformationClass,
			reinterpret_cast< std::uint64_t* >( threadInformation ),
			threadInformationLength,
			&ReturnLen )
			)
		{
			if ( returnLength )
				*returnLength = ReturnLen;

			//	printf( "[ ! ] NtQueryInformationThread - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtQueryInformationThread returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtQueryInformationThread( threadHandle, threadInformationClass, threadInformation, threadInformationLength, returnLength );
}

NTSTATUS( NTAPI* oNtSetInformationThread )( HANDLE, THREADINFOCLASS, PVOID, ULONG );

NTSTATUS NTAPI hk_NtSetInformationThread( HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength )
{
	if ( threadHandle != GetCurrentThread() && CEPTOR_VALID_HANDLE( threadHandle ) )
	{
		if ( g_cmdDriver->SetThreadInformation(
			uint64_t( threadHandle ),
			threadInformationClass,
			reinterpret_cast< std::uint64_t* >( threadInformation ),
			threadInformationLength )
			)
		{
			//printf( "[ ! ] NtSetInformationThread - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtSetInformationThread returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtSetInformationThread( threadHandle, threadInformationClass, threadInformation, threadInformationLength );
}

NTSTATUS( NTAPI* oNtGetContextThread )( HANDLE, PCONTEXT );

NTSTATUS NTAPI hk_NtGetContextThread( HANDLE threadHandle, PCONTEXT context )
{
	if ( threadHandle != GetCurrentThread() && CEPTOR_VALID_HANDLE( threadHandle ) )
	{
		if ( g_cmdDriver->GetThreadContext(
			uint64_t( threadHandle ),
			context )
			)
		{
			//printf( "[ ! ] NtGetContextThread - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtGetContextThread returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtGetContextThread( threadHandle, context );
}

NTSTATUS( NTAPI* oNtSetContextThread )( HANDLE, PCONTEXT );

NTSTATUS NTAPI hk_NtSetContextThread( HANDLE threadHandle, PCONTEXT context )
{
	if ( threadHandle != GetCurrentThread() && CEPTOR_VALID_HANDLE( threadHandle ) )
	{
		if ( g_cmdDriver->SetThreadContext(
			uint64_t( threadHandle ),
			context )
			)
		{
			//printf( "[ ! ] NtSetContextThread - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtSetContextThread returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtSetContextThread( threadHandle, context );
}

NTSTATUS( NTAPI* oNtResumeThread )( HANDLE, PULONG );

NTSTATUS NTAPI hk_NtResumeThread( HANDLE threadHandle, PULONG suspendCount )
{
	if ( threadHandle != GetCurrentThread() && CEPTOR_VALID_HANDLE( threadHandle ) )
	{
		std::uint32_t Count = NULL;
		if ( g_cmdDriver->ResumeThread(
			uint64_t( threadHandle ),
			&Count )
			)
		{
			if ( suspendCount )
				*suspendCount = Count;

			//printf( "[ ! ] NtResumeThread - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtResumeThread returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtResumeThread( threadHandle, suspendCount );
}

NTSTATUS( NTAPI* oNtSuspendThread )( HANDLE, PULONG );

NTSTATUS NTAPI hk_NtSuspendThread( HANDLE threadHandle, PULONG previousSuspendCount )
{
	if ( threadHandle != GetCurrentThread() && CEPTOR_VALID_HANDLE( threadHandle ) )
	{
		std::uint32_t Count = NULL;
		if ( g_cmdDriver->SuspendThread(
			uint64_t( threadHandle ),
			&Count )
			)
		{
			if ( previousSuspendCount )
				*previousSuspendCount = Count;

			//printf( "[ ! ] NtSuspendThread - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtSuspendThread returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtSuspendThread( threadHandle, previousSuspendCount );
}

//
// Query Information Process
//
NTSTATUS( NTAPI* oNtQueryInformationProcess )( HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG );

NTSTATUS NTAPI hk_NtQueryInformationProcess( HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength )
{
	if ( ProcessHandle != GetCurrentProcess() && CEPTOR_VALID_HANDLE( ProcessHandle ) )
	{
		if ( g_cmdDriver->QueryInformationProcess(
			uint64_t( ProcessHandle ),
			ProcessInformationClass,
			reinterpret_cast< uint64_t* >( ProcessInformation ),
			ProcessInformationLength,
			reinterpret_cast< uint32_t* >( ReturnLength ) )
			)
		{
			//printf( "[ ! ] NtQueryInformationProcess - success!\n" );
			return STATUS_SUCCESS;
		}
		else
		{
			printf( "[ ! ] NtQueryInformationProcess returned 0x%X\n", g_cmdDriver->GetLastNtError() );
			return g_cmdDriver->GetLastNtError();
		}
	}
	return oNtQueryInformationProcess( ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength );
}

NTSTATUS( NTAPI* oNtQuerySystemInformationEx )( SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PVOID, ULONG, PULONG );

NTSTATUS NTAPI hk_NtQuerySystemInformationEx( SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID inputBuffer, ULONG inputBufferLength, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength )
{
	switch ( systemInformationClass )
	{
	case 0xb5: //SystemSupportedProcessArchitectures
		if ( inputBuffer && inputBufferLength >= sizeof( HANDLE ) && CEPTOR_VALID_HANDLE( inputBuffer ) )
		{
			std::uint32_t ResLength = NULL;

			if ( g_cmdDriver->QuerySystemInformationEx(
				systemInformationClass,
				reinterpret_cast< uint64_t* >( inputBuffer ),
				inputBufferLength,
				reinterpret_cast< uint64_t* >( systemInformation ),
				systemInformationLength,
				&ResLength )
				)
			{
				if ( returnLength )
					*returnLength = ResLength;

				//printf( "[ ! ] NtQuerySystemInformationEx - success!\n" );
				return STATUS_SUCCESS;
			}
			else
			{
				printf( "[ ! ] NtQuerySystemInformationEx returned 0x%X\n", g_cmdDriver->GetLastNtError() );
				return g_cmdDriver->GetLastNtError();
			}
		}
		break;
	}
	return oNtQuerySystemInformationEx( systemInformationClass, inputBuffer, inputBufferLength, systemInformation, systemInformationLength, returnLength );
}

//
// WaitForSingleObject
//
NTSTATUS( NTAPI* oNtWaitForSingleObject )( HANDLE, BOOLEAN, PLARGE_INTEGER );

NTSTATUS NTAPI hk_NtWaitForSingleObject( HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout )
{
	auto Status = oNtWaitForSingleObject( Handle, Alertable, Timeout );
	if ( !NT_SUCCESS( Status ) )
		printf( "[ ! ] NtWaitForSingleObject - Handle: 0x%p, Status: 0x%X!\n", Handle, Status );

	return Status;
	/*if ( NT_SUCCESS( Status ) )
		return Status;

	if ( CEPTOR_VALID_HANDLE( Handle ) )
	{
		printf( "[ ! ] NtWaitForSingleObject - 0x%p!\n", Handle );

		g_cmdDriver->WaitForSingleObject(
			uint64_t( Handle ),
			Alertable,
			Timeout
		);

		return g_cmdDriver->GetLastNtError();
	}
	else
	{
		auto HandleId = GetThreadId( Handle );

		if ( HandleId )
			printf( "[ ! ] NtWaitForSingleObject - ThreadId: %d!\n", HandleId );
		else
			HandleId = GetProcessId( Handle );

		if ( HandleId )
		{
			printf( "[ ! ] NtWaitForSingleObject - ProcessId: %d!\n", HandleId );

			g_cmdDriver->WaitForSingleObject(
				uint64_t( HandleId ),
				Alertable,
				Timeout
			);

			return g_cmdDriver->GetLastNtError();
		}
		else
			printf( "[ ! ] NtWaitForSingleObject - Unknown: 0x%p!\n", Handle );
	}

	return oNtWaitForSingleObject( Handle, Alertable, Timeout );*/
}