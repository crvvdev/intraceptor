#pragma once

#include <ntimage.h>

template <typename T = uint8_t*>
inline T resolve_jxx( uint8_t* address )
{
	return reinterpret_cast< T >( address + *reinterpret_cast< int8_t* >( address + 1 ) + 2 );
}

template <typename T = uint8_t*>
inline T resolve_call( uint8_t* address )
{
	return reinterpret_cast< T >( address + *reinterpret_cast< int32_t* >( address + 1 ) + 5 );
}

template <typename T = uint8_t*>
inline T resolve_mov( uint8_t* address )
{
	return reinterpret_cast< T >( address + *reinterpret_cast< int32_t* >( address + 3 ) + 7 );
}

inline BOOLEAN FindModuleByName( LPCSTR modname, SIZE_T* base = nullptr, SIZE_T* size = nullptr )
{
	if ( !modname )
		return FALSE;

	ULONG bytes = 0;

	auto Status = ZwQuerySystemInformation( SystemModuleInformation, NULL, bytes, &bytes );
	if ( !bytes )
		return FALSE;

	const auto info = PRTL_PROCESS_MODULES( ExAllocatePool( NonPagedPool, bytes ) );

	Status = ZwQuerySystemInformation( SystemModuleInformation, info, bytes, &bytes );
	if ( !NT_SUCCESS( Status ) )
	{
		ExFreePool( info );
		return FALSE;
	}

	BOOLEAN bResult = FALSE;

	for ( ULONG i = 0; i < info->NumberOfModules; i++ )
	{
		const auto pModule = &info->Modules[ i ];

		if ( strstr( PCHAR( pModule->FullPathName ), modname ) )
		{
			if ( base )
				*base = SIZE_T( pModule->ImageBase );

			if ( size )
				*size = SIZE_T( pModule->ImageSize );

			bResult = true;
			break;
		}
	}

	if ( info )
		ExFreePool( info );

	return bResult;
}

inline BOOLEAN bDataCompare( const UCHAR* pData, const UCHAR* bMask, const char* szMask )
{
	for ( ; *szMask; ++szMask, ++pData, ++bMask )
		if ( *szMask == 'x' && *pData != *bMask )
			return 0;

	return ( *szMask ) == 0;
}

inline PUCHAR FindPattern( LPCSTR modname, LPCSTR secname, UCHAR* bMask, const char* szMask )
{
	SIZE_T base = NULL;

	if ( !modname || !secname || !bMask || !szMask )
		return nullptr;

	if ( !FindModuleByName( modname, &base ) )
		return nullptr;

	if ( !base )
		return nullptr;

	auto nth = RtlImageNtHeader( PVOID( base ) );
	if ( !nth )
		return nullptr;

	PIMAGE_SECTION_HEADER pSection = nullptr;

	auto sec = IMAGE_FIRST_SECTION( nth );
	for ( auto i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++ )
	{
		if ( !_strnicmp( reinterpret_cast< char* >( sec->Name ), secname, IMAGE_SIZEOF_SHORT_NAME ) )
		{
			pSection = sec;
			break;
		}
	}

	if ( pSection )
	{
		auto dwAddress = ( SIZE_T )( base + pSection->VirtualAddress );

		for ( auto i = 0ul; i < pSection->Misc.VirtualSize; ++i )
		{
			if ( bDataCompare( ( UCHAR* )( dwAddress + i ), bMask, szMask ) )
				return PUCHAR( dwAddress + i );
		}
	}
	return nullptr;
}