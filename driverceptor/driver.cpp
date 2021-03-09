#include "stdafx.hpp"

PDRIVER_DISPATCH	g_originalDispatcher	= nullptr;
PDRIVER_OBJECT		g_driverObject			= nullptr;

NTSTATUS IoControl( PDEVICE_OBJECT DeviceObject, PIRP Irp )
{
	UNREFERENCED_PARAMETER( DeviceObject );

	NTSTATUS Status = 1337;
	ULONG OutputLenght = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation( Irp );
	const ULONG InputLenght = stack->Parameters.DeviceIoControl.InputBufferLength;

	//	DBGPRINT( "%s %d : Recieved Ioctl 0x%X", __FUNCTION__, __LINE__, stack->Parameters.DeviceIoControl.IoControlCode );

	switch ( stack->Parameters.DeviceIoControl.IoControlCode )
	{

	case IOCTL_ATTACH_TO_PROCESS:
	{
		const auto Buffer = PATTACH_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( ATTACH_PROCESS ) )
		{
			auto TargetPid = HANDLE( Buffer->ProcessId );
			auto TargetTid = HANDLE( Buffer->ThreadId );

			if ( TargetPid && CEPTOR_VALID_HANDLE( TargetPid ) )
			{
				Status = STATUS_INVALID_HANDLE;
				goto exit;
			}

			if ( TargetPid || TargetTid )
			{
				auto List = InsertHandleListEntry( );
				if ( List )
				{
					Status = PsLookupProcessByProcessId( TargetPid, &List->Process );

					if ( NT_SUCCESS( Status ) )
					{
						Status = STATUS_PROCESS_IS_TERMINATING;

						if ( AcquireProcessSync( List->Process ) )
						{
							Buffer->OutProcessHandle = std::uint64_t( List->HandleValue );

							List->ProcessId = TargetPid;

							if ( List->Process )
								List->Wow64 = ( PsGetProcessWow64Process( List->Process ) != NULL );

							//DBGPRINT( "%s %d : IOCTL_ATTACH_TO_PROCESS - ProcessHandle: 0x%llX - returned 0x%X", __FUNCTION__, __LINE__, Buffer->OutProcessHandle, Status );
							Status = STATUS_SUCCESS;
							ReleaseProcessSync( List->Process );
						}
						else
						{
							ObDereferenceObject( List->Process );
							RemoveHandleListEntry( List );
						}
					}
					else
						RemoveHandleListEntry( List );
				}
			}

		exit:
			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_ATTACH_TO_PROCESS PID = 0x%p, TID = 0x%p, status: 0x%X", __FUNCTION__, __LINE__, TargetPid, TargetTid, Status );

			OutputLenght = sizeof( ATTACH_PROCESS );
		}
		break;
	}

	case IOCTL_DETACH_FROM_PROCESS:
	{
		const auto Buffer = PDETACH_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( DETACH_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					if ( Entry->Process )
					{
						ObDereferenceObject( Entry->Process );
						Entry->Process = nullptr;
					}

					if ( Entry->Thread )
					{
						ObDereferenceObject( Entry->Thread );
						Entry->Thread = nullptr;
					}

					RemoveHandleListEntry( Entry );
					Status = STATUS_SUCCESS;
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_DETACH_FROM_PROCESS - ProcessHandle: 0x%llX - returned 0x%X", __FUNCTION__, __LINE__, Buffer->ProcessHandle, Status );

			OutputLenght = sizeof( DETACH_PROCESS );
		}
		break;
	}

	case IOCTL_READ_MEMORY_PROCESS:
	{
		const auto Buffer = PREADMEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( READMEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					SIZE_T SizeBuf	= Buffer->Lenght;
					PVOID Address	= Buffer->BaseAddress;
					PVOID Buf		= Buffer->Buffer;

					if ( SizeBuf > 0 )
					{
						SIZE_T numberOfBytesRead = 0;

						Status = MmCopyVirtualMemory(
							Entry->Process, Address,
							PsGetCurrentProcess(),
							Buf,
							SizeBuf,
							ExGetPreviousMode(),
							&numberOfBytesRead
						);

						if ( numberOfBytesRead )
						{
							if ( Buffer->BytesRead )
								*Buffer->BytesRead = numberOfBytesRead;
						}
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_READ_MEMORY_PROCESS PID = 0x%p, ( Base = 0x%p, Buffer = 0x%p, Lenght = 0x%llX ) returned 0x%X", __FUNCTION__, __LINE__, HandleValue , Buffer->BaseAddress, Buffer->Buffer, Buffer->Lenght, Status );

			OutputLenght = sizeof( READMEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_WRITE_MEMORY_PROCESS:
	{
		const auto Buffer = PWRITEMEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( WRITEMEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					SIZE_T Lenght = SIZE_T( Buffer->Lenght );
					SIZE_T BytesWritten = NULL;
					Status = MmCopyVirtualMemory( PsGetCurrentProcess(), Buffer->Buffer, Entry->Process, Buffer->BaseAddress, Lenght, ExGetPreviousMode(), &BytesWritten );

					if ( BytesWritten )
					{
						if ( Buffer->BytesWritten )
							*Buffer->BytesWritten = BytesWritten;
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_WRITE_MEMORY_PROCESS returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( WRITEMEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_QUERY_MEMORY_PROCESS:
	{
		const auto Buffer = PQUERYMEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( QUERYMEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					PVOID BaseAddress = PVOID( Buffer->BaseAddress );
					ULONG InformationClass = ULONG( Buffer->InformationClass );
					SIZE_T Lenght = SIZE_T( Buffer->Lenght );
					SIZE_T RetLenght = NULL;

					auto MemoryInformation = PVOID( AllocateZeroPool( Lenght ) );
					if ( MemoryInformation )
					{
						if ( AcquireProcessSync( Entry->Process ) )
						{
							KAPC_STATE apc{ };
							KeStackAttachProcess( Entry->Process, &apc );
							Status = ZwQueryVirtualMemory(
								NtCurrentProcess(),
								BaseAddress,
								MEMORY_INFORMATION_CLASS( InformationClass ),
								MemoryInformation,
								Lenght,
								&RetLenght );
							KeUnstackDetachProcess( &apc );

							ReleaseProcessSync( Entry->Process );
						}

						if ( NT_SUCCESS( Status ) && RetLenght )
						{
							if( InformationClass == 2 /*MemoryMappedFilenameInformation*/ )
								AdjustRelativePointers( ( std::uint8_t *)MemoryInformation, ( std::uint8_t* )Buffer->Buffer, RetLenght );

							RtlCopyMemory( PVOID( Buffer->Buffer ), MemoryInformation, RetLenght );
						}

						ExFreePool( MemoryInformation );
					}

					if ( Buffer->ResultLength )
						*Buffer->ResultLength = RetLenght & 0xFFFFFFFF;
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_QUERY_MEMORY_PROCESS returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( QUERYMEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_QUERY_INFO_PROCESS:
	{
		const auto Buffer = PQUERYINFO_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( QUERYINFO_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					ULONG InformationClass = ULONG( Buffer->InformationClass );
					ULONG Lenght = Buffer->Lenght;
					ULONG RetLenght = NULL;

					auto ProcessInformation = PVOID( AllocateZeroPool( Lenght ) );
					if ( ProcessInformation )
					{
						if ( AcquireProcessSync( Entry->Process ) )
						{
							KAPC_STATE apc{ };
							KeStackAttachProcess( Entry->Process, &apc );

							Status = ZwQueryInformationProcess(
								NtCurrentProcess(),
								PROCESSINFOCLASS( InformationClass ),
								ProcessInformation,
								Lenght,
								&RetLenght );

							KeUnstackDetachProcess( &apc );

							if ( Buffer->ResultLength )
								*Buffer->ResultLength = RetLenght;

							ReleaseProcessSync( Entry->Process );
						}

						if ( NT_SUCCESS( Status ) )
						{
							AdjustRelativePointers( reinterpret_cast< std::uint8_t* >( ProcessInformation ), reinterpret_cast< std::uint8_t* >( Buffer->Buffer ), Lenght );
							RtlCopyMemory( PVOID( Buffer->Buffer ), ProcessInformation, Lenght );
						}

						ExFreePool( ProcessInformation );
						//					DBGPRINT( "%s %d : IOCTL_QUERY_INFO_PROCESS - InfoClass: %d, ProcessInfo = 0x%p, Lenght = 0x%X", __FUNCTION__, __LINE__, InformationClass, Buffer->Buffer, Lenght );	
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_QUERY_INFO_PROCESS returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( QUERYINFO_PROCESS );
		}
		break;
	}

	case IOCTL_QUERY_SYSTEM_INFO_EX:
	{
		const auto Buffer = PQUERY_SYSTEMINFOEX( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( QUERY_SYSTEMINFOEX ) )
		{
			ULONG RetLenght = NULL;
			SYSTEM_INFORMATION_CLASS InfoClass = SYSTEM_INFORMATION_CLASS( Buffer->InformationClass );

			ULONG InputBuffLen = Buffer->InputBufferLenght;
			ULONG SysInfoLen = Buffer->SystemInfoLenght;

			auto SystemInfo = PVOID( AllocateZeroPool( SysInfoLen ) );
			if ( SystemInfo )
			{
				switch ( InfoClass )
				{
				case SystemSupportedProcessArchitectures:
				{
					if ( CEPTOR_VALID_HANDLE( Buffer->InputBuffer ) )
					{
						auto HandleValue = HANDLE( Buffer->InputBuffer );

						if ( HandleValue )
						{
							auto Entry = FindHandleListEntry( HandleValue );
							if ( Entry )
							{
								auto processHandle = NtCurrentProcess();

								if ( AcquireProcessSync( Entry->Process ) )
								{
									KAPC_STATE apc{ };
									KeStackAttachProcess( Entry->Process, &apc );

									Status =
										ZwQuerySystemInformationEx(
											InfoClass,
											&processHandle,
											InputBuffLen,
											SystemInfo,
											SysInfoLen,
											&RetLenght );

									KeUnstackDetachProcess( &apc );

									if ( Buffer->ResultLength )
										*Buffer->ResultLength = RetLenght;

									ReleaseProcessSync( Entry->Process );
								}

								if ( NT_SUCCESS( Status ) )
									RtlCopyMemory( PVOID( Buffer->SystemInfo ), SystemInfo, SysInfoLen );
							}
						}

						//	DBGPRINT( "%s %d : IOCTL_QUERY_SYSTEM_INFO_EX - Special - returned 0x%X", __FUNCTION__, __LINE__, Status );
					}
					//else
					//	DBGPRINT( "%s %d : IOCTL_QUERY_SYSTEM_INFO_EX - SystemSupportedProcessArchitectures - Ptr: 0x%p", __FUNCTION__, __LINE__, Buffer->InputBuffer );

					break;
				}

				default:
				{
					Status = ZwQuerySystemInformationEx(
						InfoClass,
						Buffer->InputBuffer,
						Buffer->InputBufferLenght,
						SystemInfo,
						SysInfoLen,
						&RetLenght );

					if ( Buffer->ResultLength )
						*Buffer->ResultLength = RetLenght;

					if ( NT_SUCCESS( Status ) )
						RtlCopyMemory( PVOID( Buffer->SystemInfo ), SystemInfo, SysInfoLen );

					break;
				}
				}

				ExFreePool( SystemInfo );
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_QUERY_SYSTEM_INFO_EX returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( QUERY_SYSTEMINFOEX );
		}
		break;
	}

	case IOCTL_SET_INFORMATION_PROCESS:
	{
		const auto Buffer = PSETINFO_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( SETINFO_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					ULONG InformationClass = ULONG( Buffer->InformationClass );
					ULONG Lenght = Buffer->Lenght;

					auto ProcessInfo = PVOID( AllocateZeroPool( Lenght ) );
					if ( ProcessInfo )
					{
						RtlCopyMemory( ProcessInfo, PVOID( Buffer->Buffer ), Lenght );

						if ( AcquireProcessSync( Entry->Process ) )
						{
							KAPC_STATE apc{ };
							KeStackAttachProcess( Entry->Process, &apc );
							Status = ZwSetInformationProcess( NtCurrentProcess(), PROCESSINFOCLASS( InformationClass ), ProcessInfo, Lenght );
							KeUnstackDetachProcess( &apc );

							ReleaseProcessSync( Entry->Process );
						}

						ExFreePool( ProcessInfo );
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_SET_INFORMATION_PROCESS returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( SETINFO_PROCESS );
		}
		break;
	}

	case IOCTL_FLUSH_INSTRUCTION_CACHE:
	{
		const auto Buffer = PFLUSHCACHE_MEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( FLUSHCACHE_MEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					if ( AcquireProcessSync( Entry->Process ) )
					{
						PVOID BaseAddress = PVOID( Buffer->BaseAddress );
						ULONG Lenght = ULONG( Buffer->Lenght );

						KAPC_STATE apc{ };
						KeStackAttachProcess( Entry->Process, &apc );
						Status = ZwFlushInstructionCache( NtCurrentProcess(), &BaseAddress, Lenght );
						KeUnstackDetachProcess( &apc );

						ReleaseProcessSync( Entry->Process );
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_FLUSH_INSTRUCTION_CACHE returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( FLUSHCACHE_MEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_FLUSH_MEMORY_PROCESS:
	{
		const auto Buffer = PFLUSHVIRTUAL_MEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( FLUSHVIRTUAL_MEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					PVOID BaseAddress = PVOID( Buffer->BaseAddress );
					SIZE_T RegionSize = SIZE_T( Buffer->Lenght );

					auto IoStatus = PIO_STATUS_BLOCK( AllocateZeroPool( sizeof( IO_STATUS_BLOCK ) ) );
					if ( IoStatus )
					{
						if ( AcquireProcessSync( Entry->Process ) )
						{
							KAPC_STATE apc{ };
							KeStackAttachProcess( Entry->Process, &apc );
							Status = ZwFlushVirtualMemory( NtCurrentProcess(), &BaseAddress, &RegionSize, IoStatus );
							KeUnstackDetachProcess( &apc );

							ReleaseProcessSync( Entry->Process );
						}

						if ( NT_SUCCESS( Status ) && Buffer->IoStatus && MmIsAddressValid( Buffer->IoStatus ) )
							RtlCopyMemory( Buffer->IoStatus, IoStatus, sizeof( IO_STATUS_BLOCK ) );

						ExFreePool( IoStatus );
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_FLUSH_MEMORY_PROCESS returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( FLUSHVIRTUAL_MEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_ALLOCATE_MEMORY_PROCESS:
	{
		auto Buffer = PALLOCMEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( ALLOCMEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					PVOID BaseAddress = PVOID( Buffer->BaseAddress );
					SIZE_T RegionSize = SIZE_T( Buffer->Lenght );
					ULONG Type = Buffer->Type;
					ULONG Protect = Buffer->Protect;

					if ( AcquireProcessSync( Entry->Process ) )
					{
						KAPC_STATE apc{ };
						KeStackAttachProcess( Entry->Process, &apc );
						Status = ZwAllocateVirtualMemory( NtCurrentProcess(), &BaseAddress, NULL, &RegionSize, Type, Protect );
						KeUnstackDetachProcess( &apc );

						ReleaseProcessSync( Entry->Process );
					}

					if ( NT_SUCCESS( Status ) )
						Buffer->BaseAddress = std::uint64_t( BaseAddress );
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_ALLOCATE_MEMORY_PROCESS - Base: 0x%llX - returned 0x%X", __FUNCTION__, __LINE__, Buffer->BaseAddress, Status );

			OutputLenght = sizeof( ALLOCMEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_FREE_MEMORY_PROCESS:
	{
		const auto Buffer = PFREEMEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( FREEMEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					PVOID BaseAddress = PVOID( Buffer->BaseAddress );
					SIZE_T RegionSize = SIZE_T( Buffer->Lenght );
					ULONG Type = Buffer->Type;

					if ( AcquireProcessSync( Entry->Process ) )
					{
						KAPC_STATE apc{ };
						KeStackAttachProcess( Entry->Process, &apc );
						Status = ZwFreeVirtualMemory( NtCurrentProcess(), &BaseAddress, &RegionSize, Type );
						KeUnstackDetachProcess( &apc );

						ReleaseProcessSync( Entry->Process );
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_FREE_MEMORY_PROCESS returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( FREEMEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_LOCK_MEMORY_PROCESS:
	{
		const auto Buffer = PLOCKMEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( LOCKMEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					PVOID BaseAddress = PVOID( Buffer->BaseAddress );
					SIZE_T RegionSize = SIZE_T( Buffer->Lenght );
					ULONG Option = ULONG( Buffer->Option );

					if ( AcquireProcessSync( Entry->Process ) )
					{
						KAPC_STATE apc{ };
						KeStackAttachProcess( Entry->Process, &apc );
						Status = ZwLockVirtualMemory( NtCurrentProcess(), &BaseAddress, &RegionSize, Option );
						KeUnstackDetachProcess( &apc );

						ReleaseProcessSync( Entry->Process );
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_LOCK_MEMORY_PROCESS returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( LOCKMEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_UNLOCK_MEMORY_PROCESS:
	{
		const auto Buffer = PUNLOCKMEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( UNLOCKMEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					PVOID BaseAddress = PVOID( Buffer->BaseAddress );
					SIZE_T RegionSize = SIZE_T( Buffer->Lenght );
					ULONG Option = ULONG( Buffer->Option );

					if ( AcquireProcessSync( Entry->Process ) )
					{
						KAPC_STATE apc{ };
						KeStackAttachProcess( Entry->Process, &apc );
						Status = ZwUnlockVirtualMemory( NtCurrentProcess(), &BaseAddress, &RegionSize, Option );
						KeUnstackDetachProcess( &apc );

						ReleaseProcessSync( Entry->Process );
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_UNLOCK_MEMORY_PROCESS returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( UNLOCKMEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_PROTECT_MEMORY_PROCESS:
	{
		const auto Buffer = PPROTECTMEMORY_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( PROTECTMEMORY_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ProcessHandle );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					PVOID BaseAddress = PVOID( Buffer->BaseAddress );
					SIZE_T RegionSize = SIZE_T( Buffer->Lenght );
					ULONG NewAccess = ULONG( Buffer->NewAccess );
					ULONG OldAccess = NULL;

					if ( AcquireProcessSync( Entry->Process ) )
					{
						KAPC_STATE apc{ };
						KeStackAttachProcess( Entry->Process, &apc );
						Status = ZwProtectVirtualMemory( NtCurrentProcess(), &BaseAddress, &RegionSize, NewAccess, &OldAccess );
						KeUnstackDetachProcess( &apc );

						ReleaseProcessSync( Entry->Process );
					}

					if ( Buffer->OldAccess )
						*Buffer->OldAccess = OldAccess;
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_PROTECT_MEMORY_PROCESS returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( PROTECTMEMORY_PROCESS );
		}
		break;
	}

	case IOCTL_OPEN_THREAD:
	{
		const auto Buffer = POPEN_THREAD_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( OPEN_THREAD_PROCESS ) )
		{
			auto TargetProcessId = HANDLE( Buffer->ProcessId );
			auto TargetThreadId = HANDLE( Buffer->ThreadId );

			auto List = InsertHandleListEntry( );
			if ( List )
			{
				if ( TargetThreadId && TargetProcessId )
				{
					CLIENT_ID cid{ };
					cid.UniqueProcess = TargetProcessId;
					cid.UniqueThread = TargetThreadId;

					Status = PsLookupProcessThreadByCid( &cid, &List->Process, &List->Thread );
					if ( NT_SUCCESS( Status ) )
					{
						Status = STATUS_THREAD_IS_TERMINATING;

						if ( AcquireThreadSync( List->Thread ) )
						{
							List->ProcessId = TargetProcessId;
							List->Wow64 = ( PsGetProcessWow64Process( List->Process ) != NULL );
							Buffer->OutThreadHandle = std::uint64_t( List->HandleValue );
						}
						else
						{
							ObDereferenceObject( List->Process );
							ObDereferenceObject( List->Thread );
							RemoveHandleListEntry( List );
						}
					}
					else
						RemoveHandleListEntry( List );
				}
				else if ( TargetThreadId && !TargetProcessId )
				{
					Status = PsLookupThreadByThreadId( TargetThreadId, &List->Thread );
					if ( NT_SUCCESS( Status )  )
					{
						Status = STATUS_THREAD_IS_TERMINATING;

						if ( AcquireThreadSync( List->Thread ) )
						{
							List->Process = PsGetThreadProcess( List->Thread );
							List->ProcessId = TargetProcessId;
							List->Wow64 = ( PsGetProcessWow64Process( List->Process ) != NULL );
							Buffer->OutThreadHandle = std::uint64_t( List->HandleValue );
						}
						else
						{
							ObDereferenceObject( List->Thread );
							RemoveHandleListEntry( List );
						}
					}
					else
						RemoveHandleListEntry( List );
				}
				else
					Status = STATUS_INVALID_PARAMETER;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_OPEN_THREAD - returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( OPEN_THREAD_PROCESS );
		}
		break;
	}

	case IOCTL_SET_CONTEXT_THREAD:
	{
		const auto Buffer = PSET_CONTEXT_THREAD_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( SET_CONTEXT_THREAD_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ThreadHandleValue );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					if ( AcquireThreadSync( Entry->Thread ) )
					{
						if ( !Entry->Wow64 )
							Status = PsSetContextThread( Entry->Thread, Buffer->Context, UserMode );
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_SET_CONTEXT_THREAD returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( SET_CONTEXT_THREAD_PROCESS );
		}
		break;
	}

	case IOCTL_GET_CONTEXT_THREAD:
	{
		const auto Buffer = PGET_CONTEXT_THREAD_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( GET_CONTEXT_THREAD_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ThreadHandleValue );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					if ( AcquireThreadSync( Entry->Thread ) )
					{
						if ( !Entry->Wow64 )
							Status = PsGetContextThread( Entry->Thread, Buffer->Context, UserMode );
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_GET_CONTEXT_THREAD returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( GET_CONTEXT_THREAD_PROCESS );
		}
		break;
	}

	case IOCTL_SUSPEND_THREAD:
	{
		const auto Buffer = PSUSPEND_THREAD_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( SUSPEND_THREAD_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ThreadHandleValue );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					ULONG Count = NULL;

					if ( AcquireThreadSync( Entry->Thread ) )
					{
						if ( !Entry->Wow64 )
							Status = PsSuspendThread( Entry->Thread, &Count );

						if ( Buffer->Count )
							*Buffer->Count = Count;
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_SUSPEND_THREAD returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( SUSPEND_THREAD_PROCESS );
		}
		break;
	}

	case IOCTL_RESUME_THREAD:
	{
		const auto Buffer = PRESUME_THREAD_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( RESUME_THREAD_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ThreadHandleValue );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					ULONG Count = NULL;

					if ( AcquireThreadSync( Entry->Thread ) )
					{
						if ( !Entry->Wow64 )
							Status = PsResumeThread( Entry->Thread, &Count );

						if ( Buffer->Count )
							*Buffer->Count = Count;
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_RESUME_THREAD returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( RESUME_THREAD_PROCESS );
		}
		break;
	}

	case IOCTL_QUERY_THREAD_INFO:
	{
		const auto Buffer = PQUERYINFO_THREAD_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( QUERYINFO_THREAD_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ThreadHandleValue );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					if ( AcquireThreadSync( Entry->Thread ) )
					{
						PUCHAR tebBaseAddress = PUCHAR( PsGetThreadTeb( Entry->Thread ) );

						if ( Entry->Wow64 )
							tebBaseAddress += 0x2000;

						KeEnterGuardedRegion();

						std::uint8_t info[ THREAD_INFO_SIZE ] = { 0 };
						memcpy( info, PsGetCurrentThread(), THREAD_INFO_SIZE );

						for ( ULONG i = 0; i < ARRAYSIZE( THREAD_INFO_SECTIONS ); i += 2 )
						{
							ULONG start = THREAD_INFO_SECTIONS[ i ];
							ULONG end = THREAD_INFO_SECTIONS[ i + 1 ];
							memcpy( ( std::uint8_t* )PsGetCurrentThread() + start, ( std::uint8_t* )Entry->Thread + start, end - start );
						}

						ULONG ResultLen = NULL;

						Status = ZwQueryInformationThread(
							NtCurrentThread(),
							THREADINFOCLASS( Buffer->InformationClass ),
							Buffer->ThreadInfo,
							Buffer->ThreadInfoLenght,
							&ResultLen
						);

						if ( Buffer->ResultLenght )
							*Buffer->ResultLenght = ResultLen;

						if (
							NT_SUCCESS( Status ) &&
							Buffer->InformationClass == ThreadBasicInformation &&
							Buffer->ThreadInfo &&
							Buffer->ThreadInfoLenght >= sizeof( PTHREAD_BASIC_INFORMATION ) )
						{
							auto tbi = PTHREAD_BASIC_INFORMATION( Buffer->ThreadInfo );
							tbi->TebBaseAddress = tebBaseAddress;

							//	DBGPRINT( "%s %d : IOCTL_QUERY_THREAD_INFO - Copy TEB = 0x%p 0x%p", __FUNCTION__, __LINE__, tbi->TebBaseAddress, tebBaseAddress );
						}
						else
							Status = STATUS_INVALID_PARAMETER;

						for ( ULONG i = 0; i < ARRAYSIZE( THREAD_INFO_SECTIONS ); i += 2 )
						{
							ULONG start = THREAD_INFO_SECTIONS[ i ];
							ULONG end = THREAD_INFO_SECTIONS[ i + 1 ];
							ULONG len = end - start;

							memcpy( ( std::uint8_t* )Entry->Thread + start, ( std::uint8_t* )PsGetCurrentThread() + start, len );
							memcpy( ( std::uint8_t* )PsGetCurrentThread() + start, ( std::uint8_t* )info + start, len );
						}

						KeLeaveGuardedRegion();
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_QUERY_THREAD_INFO returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( QUERYINFO_THREAD_PROCESS );
		}
		break;
	}

	case IOCTL_SET_THREAD_INFO:
	{
		const auto Buffer = PSETINFO_THREAD_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( SETINFO_THREAD_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ThreadHandleValue );

			if ( HandleValue )
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					if ( AcquireThreadSync( Entry->Thread ) )
					{
						KeEnterGuardedRegion();

						switch ( Buffer->InformationClass )
						{

						case ThreadZeroTlsCell:
							Status = STATUS_NOT_IMPLEMENTED;
							break;

						case ThreadIdealProcessor:
						{
							if ( !Buffer->ThreadInfo )
							{
								Status = STATUS_INVALID_PARAMETER;
								break;
							}

							if ( Buffer->ThreadInfoLenght != sizeof( ULONG ) )
							{
								Status = STATUS_INFO_LENGTH_MISMATCH;
								break;
							}

							ULONG idealProcessor = 0;
							RtlCopyMemory( PVOID( Buffer->ThreadInfo ), &idealProcessor, sizeof( idealProcessor ) );

							Status = KeSetIdealProcessorThread( Entry->Thread, ( UCHAR )idealProcessor );
							break;
						}

						default:
							if ( NT_SUCCESS( Status = PsSuspendThread( Entry->Thread, 0 ) ) )
							{
								std::uint8_t info[ THREAD_INFO_SIZE ] = { 0 };
								memcpy( info, PsGetCurrentThread(), THREAD_INFO_SIZE );

								for ( ULONG i = 0; i < ARRAYSIZE( THREAD_INFO_SECTIONS ); i += 2 )
								{
									ULONG start = THREAD_INFO_SECTIONS[ i ];
									ULONG end = THREAD_INFO_SECTIONS[ i + 1 ];
									memcpy( ( std::uint8_t* )PsGetCurrentThread() + start, ( std::uint8_t* )Entry->Thread + start, end - start );
								}

								Status = ZwSetInformationThread(
									NtCurrentThread(),
									THREADINFOCLASS( Buffer->InformationClass ),
									Buffer->ThreadInfo,
									Buffer->ThreadInfoLenght );

								for ( ULONG i = 0; i < ARRAYSIZE( THREAD_INFO_SECTIONS ); i += 2 )
								{
									ULONG start = THREAD_INFO_SECTIONS[ i ];
									ULONG end = THREAD_INFO_SECTIONS[ i + 1 ];
									ULONG len = end - start;

									memcpy( ( std::uint8_t* )Entry->Thread + start, ( std::uint8_t* )PsGetCurrentThread() + start, len );
									memcpy( ( std::uint8_t* )PsGetCurrentThread() + start, ( std::uint8_t* )info + start, len );
								}

								PsResumeThread( Entry->Thread, 0 );
							}

							break;
						}

						KeLeaveGuardedRegion();
					}
				}
				else
					Status = STATUS_NOT_FOUND;
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_SET_THREAD_INFO returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( SETINFO_THREAD_PROCESS );
		}
		break;
	}

	case IOCTL_WAIT_FOR_OBJECT:
	{
		const auto Buffer = PWAIT_OBJECT_PROCESS( Irp->AssociatedIrp.SystemBuffer );
		if ( Buffer && InputLenght >= sizeof( WAIT_OBJECT_PROCESS ) )
		{
			auto HandleValue = HANDLE( Buffer->ObjectValue );

			HANDLE hHandle{ };

			if ( !CEPTOR_VALID_HANDLE( HandleValue ) )
			{
				PEPROCESS Process = nullptr;
				Status = PsLookupProcessByProcessId( HandleValue, &Process );
				if ( !NT_SUCCESS( Status ) )
				{
					PETHREAD Thread = nullptr;
					Status = PsLookupThreadByThreadId( HandleValue, &Thread );
					if ( NT_SUCCESS( Status ) )
					{
						Status = ObOpenObjectByPointer( Thread, 0, 0, SYNCHRONIZE, *PsThreadType, KernelMode, &hHandle );
						ObDereferenceObject( Thread );
					}
				}
				else
				{
					Status = ObOpenObjectByPointer( Process, 0, 0, SYNCHRONIZE, *PsProcessType, KernelMode, &hHandle );
					ObDereferenceObject( Process );
				}
				//	DBGPRINT( "%s %d : IOCTL_WAIT_FOR_OBJECT - NON Ceptor handle returned 0x%X", __FUNCTION__, __LINE__, Status );
			}
			else
			{
				auto Entry = FindHandleListEntry( HandleValue );
				if ( Entry )
				{
					if ( Entry->Thread )
					{
						if ( AcquireThreadSync( Entry->Thread ) )
						{
							Status = ObOpenObjectByPointer( Entry->Thread, 0, 0, SYNCHRONIZE, *PsThreadType, KernelMode, &hHandle );
						}
					}
					else if ( Entry->Process )
					{
						if ( AcquireProcessSync( Entry->Process ) )
						{
							Status = ObOpenObjectByPointer( Entry->Process, 0, 0, SYNCHRONIZE, *PsProcessType, KernelMode, &hHandle );
							ReleaseProcessSync( Entry->Process );
						}
					}
					//	DBGPRINT( "%s %d : IOCTL_WAIT_FOR_OBJECT - Ceptor found and returned 0x%X", __FUNCTION__, __LINE__, Status );
				}
				//else
				//	DBGPRINT( "%s %d : IOCTL_WAIT_FOR_OBJECT Handle: 0x%p not found.", __FUNCTION__, __LINE__, HandleValue );
			}

			if ( NT_SUCCESS( Status ) )
			{
				Status = ZwWaitForSingleObject( hHandle, Buffer->Alertable, Buffer->Timeout );
				ZwClose( hHandle );
			}

			if ( !NT_SUCCESS( Status ) )
				DBGPRINT( "%s %d : IOCTL_WAIT_FOR_OBJECT returned 0x%X", __FUNCTION__, __LINE__, Status );

			OutputLenght = sizeof( WAIT_OBJECT_PROCESS );
		}
		break;
	}

	}

	if ( Status != 1337 )
	{
		Irp->IoStatus.Status = Status;
		Irp->IoStatus.Information = OutputLenght;
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		//DBGPRINT( "%s %d : Completed request status 0x%X - SystemBuffer: 0x%p", __FUNCTION__, __LINE__, Status, Irp->AssociatedIrp.SystemBuffer );
		return Status;
	}
	//else if ( Status == 1337 )
	//	DBGPRINT( "%s %d : Something was invalid, return len: %d", __FUNCTION__, __LINE__, OutputLenght );

	return g_originalDispatcher( DeviceObject, Irp );
}

NTSTATUS IoCompletedReq( PDEVICE_OBJECT DeviceObject, PIRP irp )
{
	UNREFERENCED_PARAMETER( DeviceObject );

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest( irp, IO_NO_INCREMENT );
	return STATUS_SUCCESS;
}

void HijackDispatcher()
{
	UNICODE_STRING driver_name = RTL_CONSTANT_STRING( L"\\Driver\\klhk" );

	auto status = ObReferenceObjectByName(
		&driver_name,
		OBJ_CASE_INSENSITIVE,
		nullptr,
		0,
		*IoDriverObjectType,
		KernelMode,
		nullptr,
		( PVOID* )&g_driverObject
	);

	if ( !g_driverObject || !NT_SUCCESS( status ) )
	{
		DBGPRINT( "%s %d : ObReferenceObjectByName returned 0x%08X driver_object: 0x%016X", __FUNCTION__, __LINE__, status, g_driverObject );
		return;
	}

	//g_driverObject->DeviceObject->Flags |= DO_BUFFERED_IO;
	g_originalDispatcher = g_driverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ];
	InterlockedExchangePointer( ( volatile PVOID* )&g_driverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ], &IoControl );

	DBGPRINT( "Swapped dispatcher from 0x%llX to 0x%llX", g_originalDispatcher, g_driverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] );
}

void DriverUnload( PDRIVER_OBJECT DriverObject )
{
	UNREFERENCED_PARAMETER( DriverObject );

	if ( g_originalDispatcher && g_driverObject )
	{
		DBGPRINT( "Restored dispatcher from 0x%llX to 0x%llX", g_driverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ], g_originalDispatcher );

		InterlockedExchangePointer( ( volatile PVOID* )&g_driverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ], g_originalDispatcher );
		ObDereferenceObject( g_driverObject );
	}
}

extern "C" NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{
	UNREFERENCED_PARAMETER( RegistryPath );

	KeInitializeSpinLock( &__HANDLES_LOCK );
	__HANDLES_LIST_HEAD = InitializeHandleList();

	*( PVOID* )&PsResumeThread	= resolve_call( FindPattern( "ntoskrnl.exe", "PAGE", PUCHAR( "\xE8\x00\x00\x00\x00\xBA\x00\x00\x00\x00\x48\x8B\x4C\x24\x00\xE8\x00\x00\x00\x00\x90\x48\x85\xDB" ), "x????x????xxxx?x????xxxx" ) );
	*( PVOID* )&PsSuspendThread = resolve_call( FindPattern( "ntoskrnl.exe", "PAGE", PUCHAR( "\xE8\x00\x00\x00\x00\x48\x8B\xD7\x48\x8B\xCE\xE8\x00\x00\x00\x00\x48\x8B\xF8" ), "x????xxxxxxx????xxx" ) );

	auto sig = FindPattern( "ntoskrnl.exe", "PAGE", PUCHAR( "\x8A\x88\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xF6\xD8" ), "xx????x????xx" );
	if ( sig )
	{
		while ( *sig != 0xE8 )
			++sig;

		*( PVOID* )&KeTestAlertThread = resolve_call( sig );
	}

	DriverObject->DriverUnload = DriverUnload;
	HijackDispatcher();

	return STATUS_SUCCESS;
}