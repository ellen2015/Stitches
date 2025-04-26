#pragma once
#include "Imports.hpp"
#include "Log.hpp"

EXTERN_C_START

_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
InitializeNotify();


_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
FinalizeNotify();

EXTERN_C_END

#if defined(ALLOC_PRAGMA)

#pragma alloc_text(PAGE, InitializeNotify)
#pragma alloc_text(PAGE, FinalizeNotify)

#endif

