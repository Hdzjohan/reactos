#include <ntoskrnl.h>
#include <internal/kse.h>

#define NDEBUG
#include <debug.h>

extern ULONG InitSafeBootMode;

NTSTATUS
NTAPI
MiSnapThunk(IN PVOID DllBase,
            IN PVOID ImageBase,
            IN PIMAGE_THUNK_DATA Name,
            IN PIMAGE_THUNK_DATA Address,
            IN PIMAGE_EXPORT_DIRECTORY ExportDirectory,
            IN ULONG ExportSize,
            IN BOOLEAN SnapForwarder,
            OUT PCHAR *MissingApi);

typedef struct _KSE_PROVIDER
{
    LIST_ENTRY ProviderList;
    PKSE_SHIM Shim;
} KSE_PROVIDER, *PKSE_PROVIDER;

typedef struct _KSE_ENGINE
{
    ULONG DisableFlags; // 0x01: DisableDriverShims, 0x02: DisableDeviceShims
    ULONG State; // 0: Not Ready, 1: In Progress, 2: Ready
    ULONG Flags; // 0x02: GroupPolicyOK, 0x800: DrvShimsActive, 0x1000: DevShimsActive
    LIST_ENTRY ProvidersListHead; // list of KSE_PROVIDER
    LIST_ENTRY ShimmedDriversListHead;
    KSE_CALLBACK_ROUTINES KseCallbackRoutines;
    PVOID DeviceInfoCache;
    PVOID HardwareIdCache;
    PVOID ShimmedDriverHint;
} KSE_ENGINE, *PKSE_ENGINE;

static KSE_ENGINE KseEngine;
extern KSE_SHIM KseDsShim;

PVOID NTAPI
KsepPoolAllocateNonPaged(IN SIZE_T NumberOfBytes)
{
  return ExAllocatePool(NonPagedPool, NumberOfBytes);
}

static NTSTATUS NTAPI
KsepGetShimCallbacksForDriver(
    IN PVOID DriverStart,
    OUT PKSE_DRIVER_IO_CALLBACKS pIoCallbacks)
{
    PKSE_SHIM Shim = &KseDsShim; // FIXME
    PKSE_HOOK_COLLECTION HookCollection;
    PKSE_HOOK Hook;

    RtlZeroMemory(pIoCallbacks, sizeof(*pIoCallbacks));

    for (HookCollection = Shim->HookCollectionsArray; HookCollection->Type != KseCollectionInvalid; HookCollection++)
    {
        if (HookCollection->Type != KseCollectionCallback)
            continue;
        for (Hook = HookCollection->HookArray; Hook->Type != KseHookInvalid; Hook++)
        {
            if (Hook->Type != KseHookIRPCallback)
                continue;
            if (Hook->CallbackId == 1)
                pIoCallbacks->DriverInit = Hook->HookFunction;
            else if (Hook->CallbackId == 2)
                pIoCallbacks->DriverStartIo = Hook->HookFunction;
            else if (Hook->CallbackId == 3)
                pIoCallbacks->DriverUnload = Hook->HookFunction;
            else if (Hook->CallbackId == 4)
                pIoCallbacks->AddDevice = Hook->HookFunction;
            else if (Hook->CallbackId >= 100 && Hook->CallbackId <= 100 + IRP_MJ_MAXIMUM_FUNCTION)
                pIoCallbacks->MajorFunction[Hook->CallbackId - 100] = Hook->HookFunction;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KseShimDriverIoCallbacks(
    IN PDRIVER_OBJECT DriverObject)
{
    KSE_DRIVER_IO_CALLBACKS IoCallbacks;
    PKSE_DRIVER_IO_CALLBACKS KseCallbacks;
    ULONG i;
    NTSTATUS Status;
    DPRINT("KseShimDriverIoCallbacks(%wZ)\n", &DriverObject->DriverName);

    Status = KsepGetShimCallbacksForDriver(DriverObject->DriverStart, &IoCallbacks);
    if (NT_SUCCESS(Status))
    {
        KseCallbacks = (PKSE_DRIVER_IO_CALLBACKS)KsepPoolAllocateNonPaged(sizeof(KSE_DRIVER_IO_CALLBACKS));
        if (KseCallbacks)
        {
            if (DriverObject->DriverInit && IoCallbacks.DriverInit)
            {
                KseCallbacks->DriverInit = DriverObject->DriverInit;
                DriverObject->DriverInit = IoCallbacks.DriverInit;
            }
            if (DriverObject->DriverStartIo && IoCallbacks.DriverStartIo)
            {
                KseCallbacks->DriverStartIo = DriverObject->DriverStartIo;
                DriverObject->DriverStartIo = IoCallbacks.DriverStartIo;
            }
            if (DriverObject->DriverUnload && IoCallbacks.DriverUnload)
            {
                KseCallbacks->DriverUnload = DriverObject->DriverUnload;
                DriverObject->DriverUnload = IoCallbacks.DriverUnload;
            }
            if (DriverObject->DriverExtension->AddDevice && IoCallbacks.AddDevice)
            {
                KseCallbacks->AddDevice = DriverObject->DriverExtension->AddDevice;
                DriverObject->DriverExtension->AddDevice = IoCallbacks.AddDevice;
            }
            for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
            {
                if (DriverObject->MajorFunction[i] && IoCallbacks.MajorFunction[i])
                {
                    KseCallbacks->MajorFunction[i] = DriverObject->MajorFunction[i];
                    DriverObject->MajorFunction[i] = IoCallbacks.MajorFunction[i];
                }
            }
            IoGetDrvObjExtension(DriverObject)->KseCallbacks = KseCallbacks;
            Status = STATUS_SUCCESS;
        }
    }
    return Status;
}

static NTSTATUS NTAPI
KseShimDatabaseBootInitialize()
{
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
KsepMatchInitMachineInfo()
{
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KseVersionLieInitialize()
{
    return STATUS_SUCCESS;
}

static PKSE_DRIVER_IO_CALLBACKS NTAPI
KseGetIoCallbacks(
    IN PDRIVER_OBJECT DriverObject)
{
    return IoGetDrvObjExtension(DriverObject)->KseCallbacks;
}

static NTSTATUS NTAPI
KseSetCompletionHook(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PIO_COMPLETION_ROUTINE CompletionRoutine,
    IN PVOID Context)
{
    UNIMPLEMENTED_ONCE; // FIXME
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KseInitialize(
    IN ULONG BootPhase,
    IN PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    PLOADER_PARAMETER_EXTENSION LoaderExtension = LoaderBlock->Extension;
    NTSTATUS Status;
    ULONG Flags;

    if (InitSafeBootMode != 0 || /* Safe Boot enabled */
        NT_SUCCESS(MmIsVerifierEnabled(&Flags)) || /* Driver Verifier enabled */
        !LoaderExtension || /* No loader extension */
        LoaderExtension->Size < FIELD_OFFSET(LOADER_PARAMETER_EXTENSION, NetworkLoaderBlock) || /* Too small loader extension */
        !LoaderExtension->DrvDBImage) /* No driver database */
    {
        return STATUS_SUCCESS;
    }

    if (BootPhase == 0)
    {
        KseEngine.State = 2;
        InitializeListHead(&KseEngine.ProvidersListHead);
        InitializeListHead(&KseEngine.ShimmedDriversListHead);
        KseEngine.KseCallbackRoutines.KseGetIoCallbacksRoutine = KseGetIoCallbacks;
        KseEngine.KseCallbackRoutines.KseSetCompletionHookRoutine = KseSetCompletionHook;
        Status = KseShimDatabaseBootInitialize();
        Status = KsepMatchInitMachineInfo();
        Status = KseRegisterShim(&KseDsShim, NULL, 0);
        KseEngine.State = 1;
    }
    else if (BootPhase == 1)
    {
        Status = KseVersionLieInitialize();
        //Status = KseRegisterShim(&KseSkipDriverUnloadShim);
        KseEngine.State = 2;
    }

    DPRINT1("KseInitialize(BootPhase %d) => %08x\n", BootPhase, Status);
    return Status;
}

NTSTATUS
NTAPI
KseRegisterShim(
    IN PKSE_SHIM Shim,
    IN PVOID Ignored,
    IN ULONG Flags)
{
    return KseRegisterShimEx(Shim, Ignored, Flags, NULL);
}

NTSTATUS
NTAPI
KseRegisterShimEx(
    IN PKSE_SHIM Shim,
    IN PVOID Ignored,
    IN ULONG Flags,
    IN PVOID DriverObject OPTIONAL)
{
    PKSE_PROVIDER ProviderEntry;
    PLIST_ENTRY ListEntry;
    PLDR_DATA_TABLE_ENTRY DataTableEntry;
    PKSE_HOOK_COLLECTION HookCollection;
    PKSE_HOOK Hook;

    if (!Shim)
        return STATUS_INVALID_PARAMETER;

    if (KseEngine.State != 2)
        return STATUS_UNSUCCESSFUL;

    /* Search the loaded module associated to caller */
    for (ListEntry = PsLoadedModuleList.Flink;
         ListEntry != &PsLoadedModuleList;
         ListEntry = ListEntry->Flink)
    {
        /* Get the data table entry */
        DataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (_ReturnAddress() < DataTableEntry->DllBase)
            continue;
        if ((ULONG_PTR)_ReturnAddress() - (ULONG_PTR)DataTableEntry->DllBase >= DataTableEntry->SizeOfImage)
            continue;

        break;
    }
    if (ListEntry == &PsLoadedModuleList)
        return STATUS_NOT_FOUND;

    /* Check if all shim functions belong to caller */
    for (HookCollection = Shim->HookCollectionsArray; HookCollection->Type != KseCollectionInvalid; HookCollection++)
    {
        for (Hook = HookCollection->HookArray; Hook->Type != KseHookInvalid; Hook++)
        {
            if (Hook->HookFunction < DataTableEntry->DllBase)
                return STATUS_UNSUCCESSFUL;
            if ((ULONG_PTR)Hook->HookFunction - (ULONG_PTR)DataTableEntry->DllBase >= DataTableEntry->SizeOfImage)
                return STATUS_UNSUCCESSFUL;
        }
    }

    /* Search if shim is already loaded */
    for (ListEntry = KseEngine.ProvidersListHead.Flink;
         ListEntry != &KseEngine.ProvidersListHead;
         ListEntry = ListEntry->Flink)
    {
        ProviderEntry = CONTAINING_RECORD(ListEntry, KSE_PROVIDER, ProviderList);
        if (IsEqualGUID(ProviderEntry->Shim->ShimGuid, Shim->ShimGuid))
            return STATUS_OBJECT_NAME_COLLISION;
    }

    /* Allocate a new entry for this shim */
    ProviderEntry = ExAllocatePool(PagedPool, sizeof(KSE_PROVIDER));
    if (!ProviderEntry)
        return STATUS_INSUFFICIENT_RESOURCES;
    ProviderEntry->Shim = Shim;
    InsertTailList(&KseEngine.ProvidersListHead, &ProviderEntry->ProviderList);

    /* Now, update the shim */
    Shim->KseCallbackRoutines = &KseEngine.KseCallbackRoutines;

    if (DriverObject)
        ObReferenceObject(DriverObject);
    return STATUS_SUCCESS;
}

/* Patch one function in the iat */
static NTSTATUS NTAPI
KsePatchNewImport(
    IN PIMAGE_THUNK_DATA FirstThunk,
    IN PLDR_DATA_TABLE_ENTRY LdrEntry,
    IN PVOID ReplacementRoutine)
{
    ULONG OldProtection = 0;
    PVOID Ptr;
    SIZE_T Size;
    NTSTATUS Status;

    Ptr = &FirstThunk->u1.Function;
    Size = sizeof(FirstThunk->u1.Function);
    Status = NtProtectVirtualMemory(NtCurrentProcess(), &Ptr, &Size, PAGE_EXECUTE_READWRITE, &OldProtection);

    if (!NT_SUCCESS(Status))
{
//ASSERT(FALSE);
        //return Status;
}

    FirstThunk->u1.Function = (ULONG_PTR)ReplacementRoutine;

    Size = sizeof(FirstThunk->u1.Function);
    //Status = NtProtectVirtualMemory(NtCurrentProcess(), &Ptr, &Size, OldProtection, &OldProtection);

    if (!NT_SUCCESS(Status))
    {
        DPRINT("Unable to reprotect 0x%p\n", &FirstThunk->u1.Function);
//ASSERT(FALSE);
    }

    return STATUS_SUCCESS;
}

PVOID
NTAPI
KsepPatchImportTableEntry(
    IN PLDR_DATA_TABLE_ENTRY LdrEntry,
    IN PCSTR ModuleName,
    IN PCSTR FunctionName,
    IN PVOID ReplacementRoutine)
{
#if 1
    ULONG Size;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
    PCHAR DllBase = LdrEntry->DllBase;
    PIMAGE_THUNK_DATA OriginalThunk, FirstThunk;
    ULONG FoundCount = 0;

    ImportDescriptor = RtlImageDirectoryEntryToData(DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Size);
    if (!ImportDescriptor)
        return STATUS_SUCCESS;

    for (; ImportDescriptor->Name && ImportDescriptor->OriginalFirstThunk; ImportDescriptor++)
    {
        DPRINT("Checking ModuleName %s vs %s\n", (PCSTR)(DllBase + ImportDescriptor->Name), ModuleName);
        if (strcmp((PCSTR)(DllBase + ImportDescriptor->Name), ModuleName) != 0)
            continue;
        OriginalThunk = (PIMAGE_THUNK_DATA)(DllBase + ImportDescriptor->OriginalFirstThunk);
        FirstThunk = (PIMAGE_THUNK_DATA)(DllBase + ImportDescriptor->FirstThunk);
        /* Walk all imports */
        for (; OriginalThunk->u1.AddressOfData && FirstThunk->u1.Function; OriginalThunk++, FirstThunk++)
        {
            PIMAGE_IMPORT_BY_NAME ImportName;
if (OriginalThunk->u1.Function >= LdrEntry->SizeOfImage)
{
//ASSERT(FALSE);
break; // FIXME
}

            ImportName = (PIMAGE_IMPORT_BY_NAME)(DllBase + OriginalThunk->u1.Function);
            DPRINT("- Checking %s vs %s\n", (PCSTR)ImportName->Name, FunctionName);
            if (!strcmp((PCSTR)ImportName->Name, FunctionName))
            {
                //SeiPatchNewImport(FirstThunk, HookApi, LdrEntry);
                //MmReplaceImportEntry();
                NTSTATUS Status = KsePatchNewImport(FirstThunk, LdrEntry, ReplacementRoutine);
                DPRINT1("Found import %s@%s in %wZ. Using %p instead => status %08x\n", ModuleName, FunctionName, &LdrEntry->BaseDllName, ReplacementRoutine, Status);
                //ASSERT(FALSE);

                /* Sadly, iat does not have to be sorted, and can even contain duplicate entries. */
                FoundCount++;
            }
        }

        if (FoundCount == 1)
        {
            return (PVOID)0x1; // FIXME: OriginalValue
        }
        else
        {
            DPRINT("Failed to find %s in %wZ\n", FunctionName, &LdrEntry->BaseDllName);
#if 0
            char szOrdProcFmt[10];
            LPCSTR FuncName = SeiPrintFunctionName(HookApi->FunctionName, szOrdProcFmt);

            /* One entry not found. */
            if (!dwFound)
                SHIMENG_INFO("Entry \"%s!%s\" not found for \"%wZ\"\n", HookApi->LibraryName, FuncName, &LdrEntry->BaseDllName);
            else
                SHIMENG_INFO("Entry \"%s!%s\" found %d times for \"%wZ\"\n", HookApi->LibraryName, FuncName, dwFound, &LdrEntry->BaseDllName);
#endif
            return NULL;
        }
    }

    return NULL;
#else
    PCHAR MissingForwarder;
    IMAGE_EXPORT_DIRECTORY ExportDirectory;
    IMAGE_THUNK_DATA Name;

    Name.u1.Function = (ULONG_PTR)FunctionName;
    MiSnapThunk(LdrEntry->DllBase,
                0,
                &Name,
                NULL,
                &ExportDirectory,
                0,
                TRUE,
                &MissingForwarder);
    return STATUS_SUCCESS;
#endif
}

NTSTATUS
NTAPI
KsepPatchDriverImportsTable(
    IN PKSE_SHIM Shim,
    IN PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    PCSTR ModuleName;
    PKSE_HOOK_COLLECTION HookCollection;
    PKSE_HOOK Hook;

    if (!Shim)
        return STATUS_UNSUCCESSFUL;

    for (HookCollection = Shim->HookCollectionsArray; HookCollection->Type != KseCollectionInvalid; HookCollection++)
    {
        if (HookCollection->Type == KseCollectionCallback)
            continue;
        ModuleName = HookCollection->Type == KseCollectionNtExport ? "ntoskrnl.exe" :
                     HookCollection->Type == KseCollectionHalExport ? "hal.dll" :
                     (PCSTR)(ULONG_PTR)HookCollection->ExportDriverName; // FIXME: W->A conversion
        for (Hook = HookCollection->HookArray; Hook->Type != KseHookInvalid; Hook++)
        {
            if (Hook->Type != KseHookFunction)
                continue;
            Hook->OriginalFunction = KsepPatchImportTableEntry(LdrEntry, ModuleName, Hook->FunctionName, Hook->HookFunction);
            if (!Hook->OriginalFunction)
                return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KsepApplyShimsToDriver(
    IN PKSE_SHIM Shim,
    IN PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    if (!Shim)
        return STATUS_SUCCESS;

    KsepPatchDriverImportsTable(Shim, LdrEntry);
    //Shim->ShimmedDriverTargetedNotification();
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KseDriverLoadImage(
    IN PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    //KsepGetShimsForDriver();
    KsepApplyShimsToDriver(&KseDsShim, LdrEntry);
    //ASSERT(FALSE);
    return STATUS_NOT_SUPPORTED;
}
