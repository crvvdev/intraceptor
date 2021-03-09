#pragma once

typedef struct _HANDLES_LIST_ENTRY
{
	PETHREAD Thread;
	PEPROCESS Process;
	LIST_ENTRY Entry;
	HANDLE HandleValue;
	HANDLE ProcessId;
	BOOLEAN Wow64;

} HANDLES_LIST_ENTRY, * PHANDLES_LIST_ENTRY;

volatile LONG		__HANDLES_VALUE = 0xF0F00000;
PHANDLES_LIST_ENTRY __HANDLES_LIST_HEAD = nullptr;
KSPIN_LOCK			__HANDLES_LOCK;

PHANDLES_LIST_ENTRY InitializeHandleList()
{
	const auto List = PHANDLES_LIST_ENTRY( AllocateZeroPool( sizeof( HANDLES_LIST_ENTRY ) ) );
	if ( !List )
		return nullptr;

	DBGPRINT( "Initialized list head at 0x%p", List );
	InitializeListHead( &List->Entry );
	return List;
}

PHANDLES_LIST_ENTRY InsertHandleListEntry()
{
	const auto Entry = PHANDLES_LIST_ENTRY( AllocateZeroPool( sizeof( HANDLES_LIST_ENTRY ) ) );
	if ( !Entry )
		return nullptr;

	KIRQL oldIrql;
	KeAcquireSpinLock( &__HANDLES_LOCK, &oldIrql );
	Entry->HandleValue = ULongToHandle( InterlockedIncrement( &__HANDLES_VALUE ) );
	InsertTailList( &__HANDLES_LIST_HEAD->Entry, &Entry->Entry );
	KeReleaseSpinLock( &__HANDLES_LOCK, oldIrql );

	return Entry;
}

void RemoveHandleListEntry( PHANDLES_LIST_ENTRY Entry )
{
	if ( !Entry )
		return;

	KIRQL oldIrql;
	KeAcquireSpinLock( &__HANDLES_LOCK, &oldIrql );
	RemoveEntryList( &Entry->Entry );
	KeReleaseSpinLock( &__HANDLES_LOCK, oldIrql );
	ExFreePool( Entry );
}

PHANDLES_LIST_ENTRY FindHandleListEntry( HANDLE HandleValue )
{
	if ( IsListEmpty( &__HANDLES_LIST_HEAD->Entry ) )
		return nullptr;

	PHANDLES_LIST_ENTRY Found = nullptr;
	PLIST_ENTRY ListEntry = nullptr;

	KIRQL oldIrql;
	KeAcquireSpinLock( &__HANDLES_LOCK, &oldIrql );
	for
		(
			ListEntry = __HANDLES_LIST_HEAD->Entry.Flink;
			ListEntry != &__HANDLES_LIST_HEAD->Entry;
			ListEntry = ListEntry->Flink
			)
	{
		auto Data = CONTAINING_RECORD( ListEntry, HANDLES_LIST_ENTRY, Entry );

		if ( Data->HandleValue == HandleValue )
			Found = Data;

		if ( Found )
			break;
	}
	KeReleaseSpinLock( &__HANDLES_LOCK, oldIrql );
	return Found;
}

void ClearHandleList()
{
	// TODO..
}