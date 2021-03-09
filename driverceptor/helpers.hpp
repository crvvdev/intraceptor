#pragma once

inline PVOID AllocateZeroPool( SIZE_T size )
{
	auto PoolPtr = ExAllocatePool( NonPagedPool, size );

	if ( PoolPtr )
		RtlZeroMemory( PoolPtr, size );

	return PoolPtr;
}

inline VOID AdjustRelativePointers( std::uint8_t* buffer, std::uint8_t* target, SIZE_T size )
{
	if ( size < sizeof( PVOID ) ) {
		return;
	}

	for ( SIZE_T i = 0; i <= size - sizeof( PVOID ); i += sizeof( ULONG ) )
	{
		PVOID* ptr = ( PVOID* )( buffer + i );
		SIZE_T offset = ( std::uint8_t* ) * ptr - buffer;

		if ( offset < size ) {
			*ptr = target + offset;
			i += sizeof( ULONG );
		}
	}
}

__forceinline bool AcquireProcessSync( PEPROCESS Process )
{
	return ( PsGetProcessExitProcessCalled( Process ) == FALSE && NT_SUCCESS( PsAcquireProcessExitSynchronization( Process ) ) );
}

__forceinline void ReleaseProcessSync( PEPROCESS Process )
{
	PsReleaseProcessExitSynchronization( Process );
}

__forceinline bool AcquireThreadSync( PETHREAD Thread )
{
	return ( PsIsThreadTerminating( Thread ) == FALSE && PsGetThreadExitStatus( Thread ) == STATUS_PENDING );
}