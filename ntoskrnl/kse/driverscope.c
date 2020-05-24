#include <ntoskrnl.h>
#include <internal/kse.h>
#include <initguid.h>

//#define NDEBUG
#include <debug.h>

extern KSE_SHIM KseDsShim;

static NTSTATUS NTAPI
ShimDriverInit(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath)
{
    PDRIVER_INITIALIZE OriginalFunction;
    ASSERT(FALSE); // FIXME
    OriginalFunction = KseDsShim.KseCallbackRoutines->KseGetIoCallbacksRoutine(DriverObject)->DriverInit;
    return OriginalFunction(DriverObject, RegistryPath);
}

static VOID NTAPI
ShimDriverStartIo(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PDRIVER_OBJECT DriverObject = DeviceObject->DriverObject;
    PDRIVER_STARTIO OriginalFunction;
    OriginalFunction = KseDsShim.KseCallbackRoutines->KseGetIoCallbacksRoutine(DriverObject)->DriverStartIo;
    OriginalFunction(DeviceObject, Irp);
}

static VOID NTAPI
ShimDriverUnload(
    IN PDRIVER_OBJECT DriverObject)
{
    PDRIVER_UNLOAD OriginalFunction;
    ASSERT(FALSE); // FIXME
    OriginalFunction = KseDsShim.KseCallbackRoutines->KseGetIoCallbacksRoutine(DriverObject)->DriverUnload;
    DPRINT1("%wZ->DriverUnload()\n", &DriverObject->DriverName);
    OriginalFunction(DriverObject);
}

static NTSTATUS NTAPI
ShimDriverAddDevice(
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    PDRIVER_ADD_DEVICE OriginalFunction;
    OriginalFunction = KseDsShim.KseCallbackRoutines->KseGetIoCallbacksRoutine(DriverObject)->AddDevice;
    DPRINT1("%wZ->AddDevice(%p)\n", &DriverObject->DriverName, PhysicalDeviceObject);
    return OriginalFunction(DriverObject, PhysicalDeviceObject);
}

static NTSTATUS NTAPI
ShimIoCreateDevice(
    IN PDRIVER_OBJECT DriverObject,
    IN ULONG DeviceExtensionSize,
    IN PUNICODE_STRING DeviceName,
    IN DEVICE_TYPE DeviceType,
    IN ULONG DeviceCharacteristics,
    IN BOOLEAN Exclusive,
    OUT PDEVICE_OBJECT *DeviceObject)
{
    ASSERT(FALSE);
    return STATUS_NO_MEMORY;
}

static NTSTATUS NTAPI
ShimPoRequestPowerIrp(
    IN PDEVICE_OBJECT DeviceObject,
    IN UCHAR MinorFunction,
    IN POWER_STATE PowerState,
    IN PREQUEST_POWER_COMPLETE CompletionFunction,
    IN PVOID Context,
    OUT PIRP *Irp)
{
  NTSTATUS (*NTAPI OriginalFunction)(PDEVICE_OBJECT, UCHAR, POWER_STATE, PREQUEST_POWER_COMPLETE, PVOID, PIRP*);
  OriginalFunction = KseDsShim.HookCollectionsArray->HookArray[1].OriginalFunction;
  ASSERT(FALSE);
  return OriginalFunction(DeviceObject, MinorFunction, PowerState, CompletionFunction, Context, Irp);
}

static PVOID NTAPI
ShimExAllocatePoolWithTag(
    IN POOL_TYPE PoolType,
    IN SIZE_T NumberOfBytes,
    IN ULONG Tag)
{
  PVOID (*NTAPI OriginalFunction)(POOL_TYPE, SIZE_T, ULONG);
  OriginalFunction = KseDsShim.HookCollectionsArray->HookArray[2].OriginalFunction;
  //ASSERT(FALSE);
  return OriginalFunction(PoolType, NumberOfBytes, Tag);
}

static VOID NTAPI
ShimExFreePoolWithTag(
    IN PVOID p,
    IN ULONG Tag)
{
  VOID (*NTAPI OriginalFunction)(PVOID, ULONG);
  OriginalFunction = KseDsShim.HookCollectionsArray->HookArray[3].OriginalFunction;
  ASSERT(FALSE);
  return OriginalFunction(p, Tag);
}

static PVOID NTAPI
ShimExAllocatePool(
    IN POOL_TYPE PoolType,
    IN SIZE_T NumberOfBytes)
{
  PVOID (*NTAPI OriginalFunction)(POOL_TYPE, SIZE_T);
  OriginalFunction = KseDsShim.HookCollectionsArray->HookArray[4].OriginalFunction;
  ASSERT(FALSE);
  return OriginalFunction(PoolType, NumberOfBytes);
}

static VOID NTAPI
ShimExFreePool(
    IN PVOID p)
{
  VOID (*NTAPI OriginalFunction)(PVOID);
  OriginalFunction = KseDsShim.HookCollectionsArray->HookArray[5].OriginalFunction;
  ASSERT(FALSE);
  return OriginalFunction(p);
}

static NTSTATUS NTAPI
ShimIrpComplete(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context)
{
    ASSERT(FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS NTAPI
ShimIrp(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
    PDRIVER_OBJECT DriverObject = DeviceObject->DriverObject;
    PDRIVER_DISPATCH OriginalFunction;
    ULONG MajorFunction = IoGetCurrentIrpStackLocation(Irp)->MajorFunction;
    //ULONG MinorFunction = IoGetCurrentIrpStackLocation(Irp)->MinorFunction;
    OriginalFunction = KseDsShim.KseCallbackRoutines->KseGetIoCallbacksRoutine(DriverObject)->MajorFunction[MajorFunction];
    KseDsShim.KseCallbackRoutines->KseSetCompletionHookRoutine(DeviceObject, Irp, ShimIrpComplete, NULL);
    //DPRINT1("%wZ->Irp(MJ=%x MN=%x)\n", &DriverObject->DriverName, MajorFunction, MinorFunction);
    return OriginalFunction(DeviceObject, Irp);
}

static KSE_HOOK KseDsShimHooksNT[] = {
    { KseHookFunction, { "IoCreateDevice" }, (PVOID)(ULONG_PTR)ShimIoCreateDevice },
    { KseHookFunction, { "PoRequestPowerIrp" }, (PVOID)(ULONG_PTR)ShimPoRequestPowerIrp },
    { KseHookFunction, { "ExAllocatePoolWithTag" }, (PVOID)(ULONG_PTR)ShimExAllocatePoolWithTag },
    { KseHookFunction, { "ExFreePoolWithTag" }, (PVOID)(ULONG_PTR)ShimExFreePoolWithTag },
    { KseHookFunction, { "ExAllocatePool" }, (PVOID)(ULONG_PTR)ShimExAllocatePool },
    { KseHookFunction, { "ExFreePool" }, (PVOID)(ULONG_PTR)ShimExFreePool },
    { KseHookInvalid }
};
static KSE_HOOK KseDsShimHooksCB[] = {
    { KseHookIRPCallback, { (PCHAR)(ULONG_PTR)1 }, (PVOID)(ULONG_PTR)ShimDriverInit },
    { KseHookIRPCallback, { (PCHAR)(ULONG_PTR)2 }, (PVOID)(ULONG_PTR)ShimDriverStartIo },
    { KseHookIRPCallback, { (PCHAR)(ULONG_PTR)3 }, (PVOID)(ULONG_PTR)ShimDriverUnload },
    { KseHookIRPCallback, { (PCHAR)(ULONG_PTR)4 }, (PVOID)(ULONG_PTR)ShimDriverAddDevice },
    { KseHookIRPCallback, { (PCHAR)(ULONG_PTR)(100 + IRP_MJ_CREATE) }, (PVOID)(ULONG_PTR)ShimIrp },
    { KseHookIRPCallback, { (PCHAR)(ULONG_PTR)(100 + IRP_MJ_CLOSE) }, (PVOID)(ULONG_PTR)ShimIrp },
    { KseHookIRPCallback, { (PCHAR)(ULONG_PTR)(100 + IRP_MJ_POWER) }, (PVOID)(ULONG_PTR)ShimIrp },
    { KseHookIRPCallback, { (PCHAR)(ULONG_PTR)(100 + IRP_MJ_PNP) }, (PVOID)(ULONG_PTR)ShimIrp },
    { KseHookIRPCallback, { (PCHAR)(ULONG_PTR)(100 + IRP_MJ_DEVICE_CONTROL) }, (PVOID)(ULONG_PTR)ShimIrp },
    { KseHookInvalid }
};
static KSE_HOOK_COLLECTION KseDsShimCollections[] = {
    { KseCollectionNtExport, NULL, KseDsShimHooksNT },
    { KseCollectionCallback, NULL, KseDsShimHooksCB },
    { KseCollectionInvalid },
};

DEFINE_GUID(KseDsShimGuid, 0xbc04ab45, 0xea7e, 0x4a11, 0xa7, 0xbb, 0x97, 0x76, 0x15, 0xf4, 0xca, 0xae);

KSE_SHIM KseDsShim = { sizeof(KSE_SHIM), &KseDsShimGuid, L"DriverScope", NULL, NULL, NULL, KseDsShimCollections };

