#pragma once

#include <memory>
#include "commands_id.hpp"

class CCommand
{
private:
	HANDLE hDriver		= INVALID_HANDLE_VALUE;
	bool bInitialized	= false;
	NTSTATUS LastStatus = STATUS_SUCCESS;

	bool SendCmd( std::uint32_t dwIOCTL, std::uint64_t* Buffer, std::uint32_t Lenght )
	{
		IO_STATUS_BLOCK io{ };

		LastStatus = NtDeviceIoControlFile( 
			hDriver, nullptr, nullptr, nullptr, &io,
			dwIOCTL, Buffer, Lenght, Buffer, Lenght );

		return NT_SUCCESS( LastStatus );
	}

public:
	CCommand()
	{
		UNICODE_STRING us{ };
		RtlInitUnicodeString( &us, ( L"\\DosDevices\\Global\\KlhkCtrl" ) );

		OBJECT_ATTRIBUTES oa{ };
		InitializeObjectAttributes( &oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL );

		IO_STATUS_BLOCK io{ };
		const auto res = NtOpenFile( &hDriver, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &oa, &io, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE );
		if ( !NT_SUCCESS( res ) )
		{
			printf( "NtOpenFile failed 0x%X\n", res );
			getchar();
			return;
		}

		if ( hDriver == INVALID_HANDLE_VALUE || !hDriver  )
		{
			MessageBoxA( GetActiveWindow(), "Driver not found or loaded!", NULL, MB_ICONSTOP );
		}
		else
			bInitialized = true;
	}

	~CCommand()
	{
		if ( bInitialized )
			CloseHandle( hDriver );
	}

	bool Status() const
	{
		return bInitialized;
	}

	NTSTATUS GetLastNtError() const
	{
		return LastStatus;
	}

	bool AttachProcess( std::uint64_t ProcessId, std::uint64_t ThreadId, std::uint64_t* hProcess )
	{
		ATTACH_PROCESS cmd{ };
		cmd.ProcessId = ProcessId;
		cmd.ThreadId = ThreadId;

		const auto res = SendCmd( IOCTL_ATTACH_TO_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
		if ( res )
		{
			if ( hProcess )
				*hProcess = cmd.OutProcessHandle;
		}
		return res;
	}

	bool DetachProcess( std::uint64_t ProcessHandle )
	{
		DETACH_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;

		return SendCmd( IOCTL_DETACH_FROM_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool SuspendProcess( std::uint64_t ProcessHandle )
	{
		PROCESS_MISC cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.Suspend = TRUE;

		return SendCmd( IOCTL_SUSPEND_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool ResumeProcess( std::uint64_t ProcessHandle )
	{
		PROCESS_MISC cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.Suspend = FALSE;

		return SendCmd( IOCTL_RESUME_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool FlushInstructionCache( std::uint64_t ProcessHandle, std::uint64_t* BaseAddress, std::uint32_t Length )
	{
		FLUSHCACHE_MEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.Lenght = Length;

		return SendCmd( IOCTL_FLUSH_INSTRUCTION_CACHE, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool SetInformationProcess( std::uint64_t ProcessHandle, std::uint32_t InfoClass, std::uint64_t* ProcessInfo, std::uint32_t ProcessInfoLenght )
	{
		SETINFO_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.InformationClass = InfoClass;
		cmd.Buffer = ProcessInfo;
		cmd.Lenght = ProcessInfoLenght;

		return SendCmd( IOCTL_SET_INFORMATION_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool ReadProcessMemory( std::uint64_t ProcessHandle, std::uint64_t* BaseAddress, std::uint64_t* Buffer, std::uint64_t Lenght, std::uint64_t* BytesReaded )
	{
		READMEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.Buffer = Buffer;
		cmd.Lenght = Lenght;
		cmd.BytesRead = BytesReaded;

		return SendCmd( IOCTL_READ_MEMORY_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool WriteProcessMemory( std::uint64_t ProcessHandle, std::uint64_t* BaseAddress, std::uint64_t* Buffer, std::uint64_t Lenght, std::uint64_t* BytesWritten )
	{
		WRITEMEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.Buffer = Buffer;
		cmd.Lenght = Lenght;
		cmd.BytesWritten = BytesWritten;

		return SendCmd( IOCTL_WRITE_MEMORY_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	std::uint64_t VirtualAllocEx( std::uint64_t ProcessHandle, std::uint64_t BaseAddress, std::uint64_t Lenght, std::uint32_t Type, std::uint32_t Protect )
	{
		ALLOCMEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.Lenght = Lenght;
		cmd.Type = Type;
		cmd.Protect = Protect;

		if ( SendCmd( IOCTL_ALLOCATE_MEMORY_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) ) )
			return cmd.BaseAddress;

		return NULL;
	}

	bool FlushMemory( std::uint64_t ProcessHandle, std::uint64_t* BaseAddress, std::uint64_t Lenght, PIO_STATUS_BLOCK IoStatus )
	{
		FLUSHVIRTUAL_MEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.Lenght = Lenght;
		cmd.IoStatus = IoStatus;

		return SendCmd( IOCTL_FLUSH_MEMORY_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool VirtualLockEx( std::uint64_t ProcessHandle, std::uint64_t* BaseAddress, std::uint64_t Lenght, std::uint32_t LockOption )
	{
		LOCKMEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.Lenght = Lenght;
		cmd.Option = LockOption;

		return SendCmd( IOCTL_LOCK_MEMORY_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool VirtualUnlockEx( std::uint64_t ProcessHandle, std::uint64_t* BaseAddress, std::uint64_t Lenght, std::uint32_t LockOption )
	{
		UNLOCKMEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.Lenght = Lenght;
		cmd.Option = LockOption;

		return SendCmd( IOCTL_UNLOCK_MEMORY_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool VirtualFreeEx( std::uint64_t ProcessHandle, std::uint64_t* BaseAddress, std::uint64_t Lenght, std::uint32_t Type )
	{
		FREEMEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.Lenght = Lenght;
		cmd.Type = Type;

		return SendCmd( IOCTL_FREE_MEMORY_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool VirtualProtectEx( std::uint64_t ProcessHandle, std::uint64_t* BaseAddress, std::uint64_t Lenght, std::uint32_t NewAccess, std::uint32_t* OldAccess )
	{
		PROTECTMEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.Lenght = Lenght;
		cmd.NewAccess = NewAccess;
		cmd.OldAccess = OldAccess;

		return SendCmd( IOCTL_PROTECT_MEMORY_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool VirtualQueryEx( std::uint64_t ProcessHandle, std::uint64_t* BaseAddress, std::uint32_t InformationClass, std::uint64_t* Buffer, std::uint64_t Length, std::uint32_t* ResultLength )
	{
		QUERYMEMORY_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.BaseAddress = BaseAddress;
		cmd.InformationClass = InformationClass;
		cmd.Buffer = Buffer;
		cmd.Lenght = Length;
		cmd.ResultLength = ResultLength;

		return SendCmd( IOCTL_QUERY_MEMORY_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool QueryInformationProcess( std::uint64_t ProcessHandle, std::uint32_t InformationClass, std::uint64_t* Buffer, std::uint32_t Length, std::uint32_t* ResultLength )
	{
		QUERYINFO_PROCESS cmd{ };
		cmd.ProcessHandle = ProcessHandle;
		cmd.InformationClass = InformationClass;
		cmd.Buffer = Buffer;
		cmd.Lenght = Length;
		cmd.ResultLength = ResultLength;

		return SendCmd( IOCTL_QUERY_INFO_PROCESS, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool QuerySystemInformationEx( std::uint32_t InformationClass, std::uint64_t* InputBuffer, std::uint32_t InputBufferLenght, std::uint64_t* SystemInfo, std::uint32_t SystemInfoLenght, std::uint32_t* ResultLength )
	{
		QUERY_SYSTEMINFOEX cmd{ };
		cmd.InformationClass = InformationClass;
		cmd.InputBuffer = InputBuffer;
		cmd.InputBufferLenght = InputBufferLenght;
		cmd.SystemInfo = SystemInfo;
		cmd.SystemInfoLenght = SystemInfoLenght;
		cmd.ResultLength = ResultLength;

		return SendCmd( IOCTL_QUERY_SYSTEM_INFO_EX, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool OpenThread( std::uint64_t ThreadId, std::uint64_t ProcessId, std::uint64_t* hThreadHandle )
	{
		OPEN_THREAD_PROCESS cmd{ };
		cmd.ProcessId = ProcessId;
		cmd.ThreadId = ThreadId;

		const auto res = SendCmd( IOCTL_OPEN_THREAD, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
		if ( res )
		{
			if ( hThreadHandle )
				*hThreadHandle = cmd.OutThreadHandle;
		}
		return res;
	}

	bool GetThreadContext( std::uint64_t ThreadHandle, PCONTEXT pCtx )
	{
		GET_CONTEXT_THREAD_PROCESS cmd{ };
		cmd.ThreadHandleValue = ThreadHandle;
		cmd.Context = pCtx;

		return SendCmd( IOCTL_GET_CONTEXT_THREAD, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool SetThreadContext( std::uint64_t ThreadHandle, PCONTEXT pCtx )
	{
		SET_CONTEXT_THREAD_PROCESS cmd{ };
		cmd.ThreadHandleValue = ThreadHandle;
		cmd.Context = pCtx;

		return SendCmd( IOCTL_SET_CONTEXT_THREAD, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool ResumeThread( std::uint64_t ThreadHandle, std::uint32_t* ResumeCount )
	{
		RESUME_THREAD_PROCESS cmd{ };
		cmd.ThreadHandleValue = ThreadHandle;
		cmd.Count = ResumeCount;

		return SendCmd( IOCTL_RESUME_THREAD, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool SuspendThread( std::uint64_t ThreadHandle, std::uint32_t* SuspendCount )
	{
		SUSPEND_THREAD_PROCESS cmd{ };
		cmd.ThreadHandleValue = ThreadHandle;
		cmd.Count = SuspendCount;

		return SendCmd( IOCTL_SUSPEND_THREAD, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool QueryThreadInformation( std::uint64_t ThreadHandle, std::uint32_t InfoClass, std::uint64_t* ThreadInfo, std::uint32_t ThreadInfoLenght, std::uint32_t* ResultLenght )
	{
		QUERYINFO_THREAD_PROCESS cmd{ };
		cmd.ThreadHandleValue = ThreadHandle;
		cmd.ThreadInfo = ThreadInfo;
		cmd.ThreadInfoLenght = ThreadInfoLenght;
		cmd.ResultLenght = ResultLenght;
		cmd.InformationClass = InfoClass;

		return SendCmd( IOCTL_QUERY_THREAD_INFO, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	bool SetThreadInformation( std::uint64_t ThreadHandle, std::uint32_t InfoClass, std::uint64_t* ThreadInfo, std::uint32_t ThreadInfoLenght )
	{
		SETINFO_THREAD_PROCESS cmd{ };
		cmd.ThreadHandleValue = ThreadHandle;
		cmd.ThreadInfo = ThreadInfo;
		cmd.ThreadInfoLenght = ThreadInfoLenght;
		cmd.InformationClass = InfoClass;

		return SendCmd( IOCTL_SET_THREAD_INFO, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}

	void WaitForSingleObject( std::uint64_t ObjectId, BOOL Alertable, PLARGE_INTEGER Timeout )
	{
		WAIT_OBJECT_PROCESS cmd{ };
		cmd.ObjectValue = ObjectId;
		cmd.Alertable = Alertable;
		cmd.Timeout = Timeout;

		SendCmd( IOCTL_WAIT_FOR_OBJECT, reinterpret_cast< std::uint64_t* >( &cmd ), sizeof( cmd ) );
	}
};

extern std::unique_ptr< CCommand > g_cmdDriver;