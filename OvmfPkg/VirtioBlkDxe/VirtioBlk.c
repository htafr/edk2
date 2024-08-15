/** @file

  This driver produces Block I/O Protocol instances for virtio-blk devices.

  The implementation is basic:

  - No attach/detach (ie. removable media).

  - Although the non-blocking interfaces of EFI_BLOCK_IO2_PROTOCOL could be a
    good match for multiple in-flight virtio-blk requests, we stick to
    synchronous requests and EFI_BLOCK_IO_PROTOCOL for now.

  Copyright (C) 2012, Red Hat, Inc.
  Copyright (c) 2012 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2017, AMD Inc, All rights reserved.<BR>
  Copyright (c) 2024, Arm Limited. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <IndustryStandard/VirtioBlk.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/VirtioLib.h>

#include <hal/base.h>
#include <library/spdm_return_status.h>
#include <Stub/SpdmLibStub.h>
#include <Library/SpdmSecurityLib.h>

#include "VirtioBlk.h"
#include "VirtioBlkSpdm.h"

EDKII_DEVICE_SECURITY_POLICY_PROTOCOL  *mDeviceSecurityPolicy;

BOOLEAN  mSendReceiveBufferAcquired = FALSE;
UINT8    mSendReceiveBuffer[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
UINTN    mSendReceiveBufferSize;
VOID     *mScratchBuffer;

/**

  Convenience macros to read and write region 0 IO space elements of the
  virtio-blk device, for configuration purposes.

  The following macros make it possible to specify only the "core parameters"
  for such accesses and to derive the rest. By the time VIRTIO_CFG_WRITE()
  returns, the transaction will have been completed.

  @param[in] Dev       Pointer to the VBLK_DEV structure whose VirtIo space
                       we're accessing. Dev->VirtIo must be valid.

  @param[in] Field     A field name from VBLK_HDR, identifying the virtio-blk
                       configuration item to access.

  @param[in] Value     (VIRTIO_CFG_WRITE() only.) The value to write to the
                       selected configuration item.

  @param[out] Pointer  (VIRTIO_CFG_READ() only.) The object to receive the
                       value read from the configuration item. Its type must be
                       one of UINT8, UINT16, UINT32, UINT64.


  @return  Status code returned by Virtio->WriteDevice() /
           Virtio->ReadDevice().

**/

#define VIRTIO_CFG_WRITE(Dev, Field, Value)  ((Dev)->VirtIo->WriteDevice ( \
                                                (Dev)->VirtIo,             \
                                                OFFSET_OF_VBLK (Field),    \
                                                SIZE_OF_VBLK (Field),      \
                                                (Value)                    \
                                                ))

#define VIRTIO_CFG_READ(Dev, Field, Pointer)  ((Dev)->VirtIo->ReadDevice ( \
                                                (Dev)->VirtIo,             \
                                                OFFSET_OF_VBLK (Field),    \
                                                SIZE_OF_VBLK (Field),      \
                                                sizeof *(Pointer),         \
                                                (Pointer)                  \
                                                ))

//
// UEFI Spec 2.3.1 + Errata C, 12.8 EFI Block I/O Protocol
// Driver Writer's Guide for UEFI 2.3.1 v1.01,
//   24.2 Block I/O Protocol Implementations
//
EFI_STATUS
EFIAPI
VirtioBlkReset (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN BOOLEAN                ExtendedVerification
  )
{
  //
  // If we managed to initialize and install the driver, then the device is
  // working correctly.
  //
  return EFI_SUCCESS;
}

/**

  Verify correctness of the read/write (not flush) request submitted to the
  EFI_BLOCK_IO_PROTOCOL instance.

  This function provides most verification steps described in:

    UEFI Spec 2.3.1 + Errata C, 12.8 EFI Block I/O Protocol, 12.8 EFI Block I/O
    Protocol,
    - EFI_BLOCK_IO_PROTOCOL.ReadBlocks()
    - EFI_BLOCK_IO_PROTOCOL.WriteBlocks()

    Driver Writer's Guide for UEFI 2.3.1 v1.01,
    - 24.2.2. ReadBlocks() and ReadBlocksEx() Implementation
    - 24.2.3 WriteBlocks() and WriteBlockEx() Implementation

  Request sizes are limited to 1 GB (checked). This is not a practical
  limitation, just conformance to virtio-0.9.5, 2.3.2 Descriptor Table: "no
  descriptor chain may be more than 2^32 bytes long in total".

  Some Media characteristics are hardcoded in VirtioBlkInit() below (like
  non-removable media, no restriction on buffer alignment etc); we rely on
  those here without explicit mention.

  @param[in] Media               The EFI_BLOCK_IO_MEDIA characteristics for
                                 this driver instance, extracted from the
                                 underlying virtio-blk device at initialization
                                 time. We validate the request against this set
                                 of attributes.


  @param[in] Lba                 Logical Block Address: number of logical
                                 blocks to skip from the beginning of the
                                 device.

  @param[in] PositiveBufferSize  Size of buffer to transfer, in bytes. The
                                 caller is responsible to ensure this parameter
                                 is positive.

  @param[in] RequestIsWrite      TRUE iff data transfer goes from guest to
                                 device.


  @@return                       Validation result to be forwarded outwards by
                                 ReadBlocks() and WriteBlocks, as required by
                                 the specs above.

**/
STATIC
EFI_STATUS
EFIAPI
VerifyReadWriteRequest (
  IN  EFI_BLOCK_IO_MEDIA  *Media,
  IN  EFI_LBA             Lba,
  IN  UINTN               PositiveBufferSize,
  IN  BOOLEAN             RequestIsWrite
  )
{
  UINTN  BlockCount;

  ASSERT (PositiveBufferSize > 0);

  if ((PositiveBufferSize > SIZE_1GB) ||
      (PositiveBufferSize % Media->BlockSize > 0))
  {
    return EFI_BAD_BUFFER_SIZE;
  }

  BlockCount = PositiveBufferSize / Media->BlockSize;

  //
  // Avoid unsigned wraparound on either side in the second comparison.
  //
  if ((Lba > Media->LastBlock) || (BlockCount - 1 > Media->LastBlock - Lba)) {
    return EFI_INVALID_PARAMETER;
  }

  if (RequestIsWrite && Media->ReadOnly) {
    return EFI_WRITE_PROTECTED;
  }

  return EFI_SUCCESS;
}

/**

  Format a read / write / flush request as three consecutive virtio
  descriptors, push them to the host, and poll for the response.

  This is the main workhorse function. Two use cases are supported, read/write
  and flush. The function may only be called after the request parameters have
  been verified by
  - specific checks in ReadBlocks() / WriteBlocks() / FlushBlocks(), and
  - VerifyReadWriteRequest() (for read/write only).

  Parameters handled commonly:

    @param[in] Dev             The virtio-blk device the request is targeted
                               at.

  Flush request:

    @param[in] Lba             Must be zero.

    @param[in] BufferSize      Must be zero.

    @param[in out] Buffer      Ignored by the function.

    @param[in] RequestIsWrite  Must be TRUE.

  Read/Write request:

    @param[in] Lba             Logical Block Address: number of logical blocks
                               to skip from the beginning of the device.

    @param[in] BufferSize      Size of buffer to transfer, in bytes. The caller
                               is responsible to ensure this parameter is
                               positive.

    @param[in out] Buffer      The guest side area to read data from the device
                               into, or write data to the device from.

    @param[in] RequestIsWrite  TRUE iff data transfer goes from guest to
                               device.

  Return values are common to both use cases, and are appropriate to be
  forwarded by the EFI_BLOCK_IO_PROTOCOL functions (ReadBlocks(),
  WriteBlocks(), FlushBlocks()).


  @retval EFI_SUCCESS          Transfer complete.

  @retval EFI_DEVICE_ERROR     Failed to notify host side via VirtIo write, or
                               unable to parse host response, or host response
                               is not VIRTIO_BLK_S_OK or failed to map Buffer
                               for a bus master operation.

**/
STATIC
EFI_STATUS
EFIAPI
SynchronousRequest (
  IN              VBLK_DEV  *Dev,
  IN              EFI_LBA   Lba,
  IN              UINTN     BufferSize,
  IN OUT volatile VOID      *Buffer,
  IN              BOOLEAN   RequestIsWrite,
  IN              BOOLEAN   RequestIsSpdm
  )
{
  UINT32                   BlockSize;
  volatile VIRTIO_BLK_REQ  *Request;
  volatile UINT8           *HostStatus;
  VOID                     *HostStatusBuffer;
  DESC_INDICES             Indices;
  VOID                     *RequestMapping;
  VOID                     *StatusMapping;
  VOID                     *BufferMapping;
  EFI_PHYSICAL_ADDRESS     BufferDeviceAddress;
  EFI_PHYSICAL_ADDRESS     HostStatusDeviceAddress;
  EFI_PHYSICAL_ADDRESS     RequestDeviceAddress;
  EFI_STATUS               Status;
  EFI_STATUS               UnmapStatus;

  BlockSize = Dev->BlockIoMedia.BlockSize;

  //
  // Set BufferMapping and BufferDeviceAddress to suppress incorrect
  // compiler/analyzer warnings.
  //
  BufferMapping       = NULL;
  BufferDeviceAddress = 0;

  //
  // ensured by VirtioBlkInit()
  //
  ASSERT (BlockSize > 0);
  ASSERT (BlockSize % 512 == 0);

  //
  // ensured by contract above, plus VerifyReadWriteRequest()
  //
  ASSERT (BufferSize % BlockSize == 0);

  Request = AllocateZeroPool (sizeof (*Request));
  if (Request == NULL) {
    return EFI_DEVICE_ERROR;
  }

  //
  // Prepare virtio-blk request header, setting zero size for flush.
  // IO Priority is homogeneously 0.
  //
  Request.Type = RequestIsWrite ?
                 (BufferSize == 0 ? VIRTIO_BLK_T_FLUSH : VIRTIO_BLK_T_OUT) :
                 VIRTIO_BLK_T_IN;
  if (RequestIsSpdm) Request.Type &= VIRTIO_BLK_T_SPDM;
  Request.IoPrio = 0;
  Request.Sector = MultU64x32 (Lba, BlockSize / 512);

  //
  // Host status is bi-directional (we preset with a value and expect the
  // device to update it). Allocate a host status buffer which can be mapped
  // to access equally by both processor and the device.
  //
  Status = Dev->VirtIo->AllocateSharedPages (
                          Dev->VirtIo,
                          EFI_SIZE_TO_PAGES (sizeof *HostStatus),
                          &HostStatusBuffer
                          );
  if (EFI_ERROR (Status)) {
    Status = EFI_DEVICE_ERROR;
    goto FreeBlkRequest;
  }

  HostStatus = HostStatusBuffer;

  //
  // Map virtio-blk request header (must be done after request header is
  // populated)
  //
  Status = VirtioMapAllBytesInSharedBuffer (
             Dev->VirtIo,
             VirtioOperationBusMasterRead,
             (VOID *)Request,
             sizeof (*Request),
             &RequestDeviceAddress,
             &RequestMapping
             );
  if (EFI_ERROR (Status)) {
    Status = EFI_DEVICE_ERROR;
    goto FreeHostStatusBuffer;
  }

  //
  // Map data buffer
  //
  if (BufferSize > 0) {
    Status = VirtioMapAllBytesInSharedBuffer (
               Dev->VirtIo,
               (RequestIsWrite ?
                VirtioOperationBusMasterRead :
                VirtioOperationBusMasterWrite),
               (VOID *)Buffer,
               BufferSize,
               &BufferDeviceAddress,
               &BufferMapping
               );
    if (EFI_ERROR (Status)) {
      Status = EFI_DEVICE_ERROR;
      goto UnmapRequestBuffer;
    }
  }

  //
  // preset a host status for ourselves that we do not accept as success
  //
  *HostStatus = VIRTIO_BLK_S_IOERR;

  //
  // Map the Status Buffer with VirtioOperationBusMasterCommonBuffer so that
  // both processor and device can access it.
  //
  Status = VirtioMapAllBytesInSharedBuffer (
             Dev->VirtIo,
             VirtioOperationBusMasterCommonBuffer,
             HostStatusBuffer,
             sizeof *HostStatus,
             &HostStatusDeviceAddress,
             &StatusMapping
             );
  if (EFI_ERROR (Status)) {
    Status = EFI_DEVICE_ERROR;
    goto UnmapDataBuffer;
  }

  VirtioPrepare (&Dev->Ring, &Indices);

  //
  // ensured by VirtioBlkInit() -- this predicate, in combination with the
  // lock-step progress, ensures we don't have to track free descriptors.
  //
  ASSERT (Dev->Ring.QueueSize >= 3);

  //
  // virtio-blk header in first desc
  //
  VirtioAppendDesc (
    &Dev->Ring,
    RequestDeviceAddress,
    sizeof (*Request),
    VRING_DESC_F_NEXT,
    &Indices
    );

  //
  // data buffer for read/write in second desc
  //
  if (BufferSize > 0) {
    //
    // From virtio-0.9.5, 2.3.2 Descriptor Table:
    // "no descriptor chain may be more than 2^32 bytes long in total".
    //
    // The predicate is ensured by the call contract above (for flush), or
    // VerifyReadWriteRequest() (for read/write). It also implies that
    // converting BufferSize to UINT32 will not truncate it.
    //
    ASSERT (BufferSize <= SIZE_1GB);

    //
    // VRING_DESC_F_WRITE is interpreted from the host's point of view.
    //
    VirtioAppendDesc (
      &Dev->Ring,
      BufferDeviceAddress,
      (UINT32)BufferSize,
      VRING_DESC_F_NEXT | (RequestIsWrite ? 0 : VRING_DESC_F_WRITE),
      &Indices
      );
  }

  //
  // host status in last (second or third) desc
  //
  VirtioAppendDesc (
    &Dev->Ring,
    HostStatusDeviceAddress,
    sizeof *HostStatus,
    VRING_DESC_F_WRITE,
    &Indices
    );

  //
  // virtio-blk's only virtqueue is #0, called "requestq" (see Appendix D).
  //
  if ((VirtioFlush (
         Dev->VirtIo,
         0,
         &Dev->Ring,
         &Indices,
         NULL
         ) == EFI_SUCCESS) &&
      (*HostStatus == VIRTIO_BLK_S_OK))
  {
    Status = EFI_SUCCESS;
  } else {
    Status = EFI_DEVICE_ERROR;
  }

  Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, StatusMapping);

UnmapDataBuffer:
  if (BufferSize > 0) {
    UnmapStatus = Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, BufferMapping);
    if (EFI_ERROR (UnmapStatus) && !RequestIsWrite && !EFI_ERROR (Status)) {
      //
      // Data from the bus master may not reach the caller; fail the request.
      //
      Status = EFI_DEVICE_ERROR;
    }
  }

UnmapRequestBuffer:
  Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, RequestMapping);

FreeHostStatusBuffer:
  Dev->VirtIo->FreeSharedPages (
                 Dev->VirtIo,
                 EFI_SIZE_TO_PAGES (sizeof *HostStatus),
                 HostStatusBuffer
                 );

FreeBlkRequest:
  FreePool ((VOID *)Request);

  return Status;
}

/**

  ReadBlocks() operation for virtio-blk.

  See
  - UEFI Spec 2.3.1 + Errata C, 12.8 EFI Block I/O Protocol, 12.8 EFI Block I/O
    Protocol, EFI_BLOCK_IO_PROTOCOL.ReadBlocks().
  - Driver Writer's Guide for UEFI 2.3.1 v1.01, 24.2.2. ReadBlocks() and
    ReadBlocksEx() Implementation.

  Parameter checks and conformant return values are implemented in
  VerifyReadWriteRequest() and SynchronousRequest().

  A zero BufferSize doesn't seem to be prohibited, so do nothing in that case,
  successfully.

**/
EFI_STATUS
EFIAPI
VirtioBlkReadBlocks (
  IN  EFI_BLOCK_IO_PROTOCOL  *This,
  IN  UINT32                 MediaId,
  IN  EFI_LBA                Lba,
  IN  UINTN                  BufferSize,
  OUT VOID                   *Buffer
  )
{
  VBLK_DEV    *Dev;
  EFI_STATUS  Status;

  if (BufferSize == 0) {
    return EFI_SUCCESS;
  }

  Dev    = VIRTIO_BLK_FROM_BLOCK_IO (This);
  Status = VerifyReadWriteRequest (
             &Dev->BlockIoMedia,
             Lba,
             BufferSize,
             FALSE               // RequestIsWrite
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return SynchronousRequest (
           Dev,
           Lba,
           BufferSize,
           Buffer,
           FALSE,       // RequestIsWrite
           FALSE
           );
}

/**

  WriteBlocks() operation for virtio-blk.

  See
  - UEFI Spec 2.3.1 + Errata C, 12.8 EFI Block I/O Protocol, 12.8 EFI Block I/O
    Protocol, EFI_BLOCK_IO_PROTOCOL.WriteBlocks().
  - Driver Writer's Guide for UEFI 2.3.1 v1.01, 24.2.3 WriteBlocks() and
    WriteBlockEx() Implementation.

  Parameter checks and conformant return values are implemented in
  VerifyReadWriteRequest() and SynchronousRequest().

  A zero BufferSize doesn't seem to be prohibited, so do nothing in that case,
  successfully.

**/
EFI_STATUS
EFIAPI
VirtioBlkWriteBlocks (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN UINT32                 MediaId,
  IN EFI_LBA                Lba,
  IN UINTN                  BufferSize,
  IN VOID                   *Buffer
  )
{
  VBLK_DEV    *Dev;
  EFI_STATUS  Status;

  if (BufferSize == 0) {
    return EFI_SUCCESS;
  }

  Dev    = VIRTIO_BLK_FROM_BLOCK_IO (This);
  Status = VerifyReadWriteRequest (
             &Dev->BlockIoMedia,
             Lba,
             BufferSize,
             TRUE                // RequestIsWrite
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return SynchronousRequest (
           Dev,
           Lba,
           BufferSize,
           Buffer,
           TRUE,        // RequestIsWrite
           FALSE
           );
}

/**

  FlushBlocks() operation for virtio-blk.

  See
  - UEFI Spec 2.3.1 + Errata C, 12.8 EFI Block I/O Protocol, 12.8 EFI Block I/O
    Protocol, EFI_BLOCK_IO_PROTOCOL.FlushBlocks().
  - Driver Writer's Guide for UEFI 2.3.1 v1.01, 24.2.4 FlushBlocks() and
    FlushBlocksEx() Implementation.

  If the underlying virtio-blk device doesn't support flushing (ie.
  write-caching), then this function should not be called by higher layers,
  according to EFI_BLOCK_IO_MEDIA characteristics set in VirtioBlkInit().
  Should they do nonetheless, we do nothing, successfully.

**/
EFI_STATUS
EFIAPI
VirtioBlkFlushBlocks (
  IN EFI_BLOCK_IO_PROTOCOL  *This
  )
{
  VBLK_DEV  *Dev;

  Dev = VIRTIO_BLK_FROM_BLOCK_IO (This);
  return Dev->BlockIoMedia.WriteCaching ?
         SynchronousRequest (
           Dev,
           0,      // Lba
           0,      // BufferSize
           NULL,   // Buffer
           TRUE,   // RequestIsWrite
           FALSE
           ) :
         EFI_SUCCESS;
}

/**
  Record an SPDM device into device list.

  @param[in]  SpdmContext       The SPDM context for the device.
**/
VOID
RecordSpdmDeviceInList (
  IN SPDM_DRIVER_DEVICE_CONTEXT  *SpdmDriverContext
  )
{
  SPDM_DEVICE_INSTANCE  *NewSpdmDevice;
  LIST_ENTRY            *SpdmDeviceList;

  SpdmDeviceList = &mSpdmDeviceList;

  NewSpdmDevice = AllocateZeroPool (sizeof (*NewSpdmDevice));
  if (NewSpdmDevice == NULL) {
    ASSERT (NewSpdmDevice != NULL);
    return;
  }

  NewSpdmDevice->Signature         = SPDM_DEVICE_INSTANCE_SIGNATURE;
  NewSpdmDevice->SpdmDriverContext = SpdmDriverContext;

  InsertTailList (SpdmDeviceList, &NewSpdmDevice->Link);
}

SPDM_RETURN
VirtioBlkSpdmSendMessage (
  IN VOID            *SpdmContext,
  IN UINTN           MessageSize,
  IN OUT CONST VOID  *Message,
  IN UINT64          Timeout
  )
{
  VBLK_DEV   *Dev;
  EFI_LBA    Lba;
  EFI_STATUS Status;

  Lba = 0;

  if (MessageSize == 0) {
    return SpdmReturn;
  }

  // WARN: when verifying the blocksize may lead to an error
  Dev = VIRTIO_BLK_FROM_SPDM_CONTEXT (SpdmContext);
  Status = VerifyReadWriteRequest (
            &Dev->BlockIoMedia,
            Lba,
            MessageSize,
            TRUE
            );
  if (EFI_ERROR (Status)) {
    return LIBSPDM_STATUS_SEND_FAIL;
  }

  Status = SynchronousRequest (
            Dev,
            Lba,
            MessageSize,
            Message,
            TRUE,       // RequestIsWrite
            TRUE
            );
  if (EFI_ERROR (Status)) {
    return LIBSPDM_STATUS_SEND_FAIL;
  }

  return LIBSPDM_STATUS_SUCCESS;
}

SPDM_RETURN
VirtioBlkSpdmReceiveMessage (
  IN     VOID    *SpdmContext,
  IN OUT UINTN   *MessageSize,
  IN OUT VOID    **Message,
  IN     UINT64  Timeout
  )
{
  VBLK_DEV    *Dev;
  EFI_LBA     Lba;
  EFI_STATUS  Status;

  if (*MessageSize == 0) {
    return EFI_SUCCESS;
  }

  Dev = VIRTIO_BLK_FROM_SPDM_CONTEXT (SpdmContext);
  Status = VerifyReadWriteRequest (
             &Dev->BlockIoMedia,
             Lba,
             *MessageSizeSize,
             FALSE               // RequestIsWrite
             );
  if (EFI_ERROR (Status)) {
    return LIBSPDM_STATUS_RECEIVE_FAIL;
  }

  Status = SynchronousRequest (
            Dev,
            Lba,
            *MessageSize,
            *Message,
            FALSE,       // RequestIsWrite
            TRUE
            );
  if (EFI_ERROR (Status)) {
    return LIBSPDM_STATUS_RECEIVE_FAIL;
  }

  return LIBSPDM_STATUS_SUCCESS;
}

SPDM_RETURN
SpdmDeviceAcquireSenderBuffer (
  VOID   *Context,
  UINTN  *MaxMsgSize,
  VOID   **MsgBufPtr
  )
{
  ASSERT (!mSendReceiveBufferAcquired);
  *MaxMsgSize = sizeof (mSendReceiveBuffer);
  *MsgBufPtr  = mSendReceiveBuffer;
  ZeroMem (mSendReceiveBuffer, sizeof (mSendReceiveBuffer));
  mSendReceiveBufferAcquired = TRUE;

  return LIBSPDM_STATUS_SUCCESS;
}

VOID
SpdmDeviceReleaseSenderBuffer (
  VOID        *Context,
  CONST VOID  *MsgBufPtr
  )
{
  ASSERT (mSendReceiveBufferAcquired);
  ASSERT (MsgBufPtr == mSendReceiveBuffer);
  mSendReceiveBufferAcquired = FALSE;

  return;
}

SPDM_RETURN
SpdmDeviceAcquireReceiverBuffer (
  VOID   *Context,
  UINTN  *MaxMsgSize,
  VOID   **MsgBufPtr
  )
{
  ASSERT (!mSendReceiveBufferAcquired);
  *MaxMsgSize = sizeof (mSendReceiveBuffer);
  *MsgBufPtr  = mSendReceiveBuffer;
  ZeroMem (mSendReceiveBuffer, sizeof (mSendReceiveBuffer));
  mSendReceiveBufferAcquired = TRUE;

  return LIBSPDM_STATUS_SUCCESS;
}

VOID
SpdmDeviceReleaseReceiverBuffer (
  VOID        *context,
  CONST VOID  *MsgBufPtr
  )
{
  ASSERT (mSendReceiveBufferAcquired);
  ASSERT (MsgBufPtr == mSendReceiveBuffer);
  mSendReceiveBufferAcquired = FALSE;

  return;
}

/**
  This function creates the SPDM device contenxt.

  @param[in]  DeviceId               The Identifier for the device.

  @return SPDM device context
**/
SPDM_DRIVER_DEVICE_CONTEXT *
CreateSpdmDriverContext (
  IN EDKII_DEVICE_IDENTIFIER  *DeviceId
  )
{
  SPDM_DRIVER_DEVICE_CONTEXT  *SpdmDriverContext;
  VOID                        *SpdmContext;
  EFI_STATUS                  Status;
  SPDM_RETURN                 SpdmReturn;
  VOID                        *Data;
  UINTN                       DataSize;
  SPDM_DATA_PARAMETER         Parameter;
  UINT8                       Data8;
  UINT16                      Data16;
  UINT32                      Data32;
  BOOLEAN                     HasRspPubCert;
  UINTN                       ScratchBufferSize;
  BOOLEAN                     IsRequrester;

  SpdmDriverContext = AllocateZeroPool (sizeof (*SpdmDriverContext));
  if (SpdmDriverContext == NULL) {
    ASSERT (SpdmDriverContext != NULL);
    return NULL;
  }

  SpdmContext = AllocateZeroPool (SpdmGetContextSize ());
  if (SpdmContext == NULL) {
    ASSERT (SpdmContext != NULL);
    FreePool (SpdmDriverContext);
    return NULL;
  }

  SpdmInitContext (SpdmContext);

  ScratchBufferSize = SpdmGetSizeofRequiredScratchBuffer (SpdmContext);
  mScratchBuffer    = AllocateZeroPool (ScratchBufferSize);
  ASSERT (mScratchBuffer != NULL);

  SpdmRegisterDeviceIoFunc (SpdmContext, SpdmDeviceSendMessage, SpdmDeviceReceiveMessage);
  SpdmRegisterTransportLayerFunc (SpdmContext, SpdmTransportMctpEncodeMessage, SpdmTransportMctpDecodeMessage);
  /*
  SpdmRegisterTransportLayerFunc (
    SpdmContext,
    SpdmTransportPciDoeEncodeMessage,
    SpdmTransportPciDoeDecodeMessage,
    SpdmTransportPciDoeGetHeaderSize
    );
  */
  SpdmRegisterDeviceBufferFunc (
    SpdmContext,
    SpdmDeviceAcquireSenderBuffer,
    SpdmDeviceReleaseSenderBuffer,
    SpdmDeviceAcquireReceiverBuffer,
    SpdmDeviceReleaseReceiverBuffer
    );
  SpdmSetScratchBuffer (SpdmContext, mScratchBuffer, ScratchBufferSize);

  SpdmDriverContext->SpdmContext = SpdmContext;

  SpdmDriverContext->Signature = SPDM_DRIVER_DEVICE_CONTEXT_SIGNATURE;
  CopyMem (&SpdmDriverContext->DeviceId, DeviceId, sizeof (*DeviceId));

  Status = gBS->HandleProtocol (
                  DeviceId->DeviceHandle,
                  &gSpdmIoProtocolGuid,
                  (VOID **)&SpdmDriverContext->SpdmIoProtocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Locate - SpdmIoProtocol - %r\n", Status));
    goto Error;
  }

  Status = gBS->HandleProtocol (
                  DeviceId->DeviceHandle,
                  &gSpdmProtocolGuid,
                  (VOID **)&SpdmDriverContext->SpdmProtocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Locate - SpdmProtocol - %r\n", Status));
    goto Error;
  }

  Status = gBS->HandleProtocol (
                  DeviceId->DeviceHandle,
                  &gEfiDevicePathProtocolGuid,
                  (VOID **)&SpdmDriverContext->DevicePath
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Locate - DevicePath - %r\n", Status));
    goto Error;
  }

  #define SPDM_UID  1// TBD - hardcoded
  SpdmDriverContext->DeviceUID = SPDM_UID;

  Status = gBS->HandleProtocol (
                  DeviceId->DeviceHandle,
                  &DeviceId->DeviceType,
                  (VOID **)&SpdmDriverContext->DeviceIo
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Locate - DeviceIo - %r\n", Status));
    // This is optional, only check known device type later.
  }

  if (CompareGuid (&DeviceId->DeviceType, &gEdkiiDeviceIdentifierTypePciGuid) ||
      CompareGuid (&DeviceId->DeviceType, &gEdkiiDeviceIdentifierTypeUsbGuid))
  {
    if (SpdmDriverContext->DeviceIo == NULL) {
      DEBUG ((DEBUG_ERROR, "Locate - PciIo - %r\n", Status));
      goto Error;
    }
  }

  //
  // Record list before any transaction
  //
  RecordSpdmDeviceInList (SpdmDriverContext);



  Status = GetVariable2 (
             L"ProvisionSpdmCertChain",
             &gEfiDeviceSecurityPkgTestConfig,
             &Data,
             &DataSize
             );
  if (!EFI_ERROR (Status)) {
    HasRspPubCert = TRUE;
    ZeroMem (&Parameter, sizeof (Parameter));
    Parameter.location = SpdmDataLocationLocal;
    SpdmSetData (SpdmContext, SpdmDataPeerPublicCertChains, &Parameter, Data, DataSize);
    // Do not free it.
  } else {
    HasRspPubCert = FALSE;
  }

  CHAR8 Message[5] = {0x05, 0x10, 0x84, 0x00, 0x00};
  VirtioBlkSpdmSendMessage (SpdmContext, sizeof (Message), &Message, 10);

  /*
  Data8 = 0;
  ZeroMem (&Parameter, sizeof (Parameter));
  Parameter.location = SpdmDataLocationLocal;
  SpdmSetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, sizeof (Data8));

  Data32 = 0 |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
           //           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
           //           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
#endif
           //           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
           //           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
           //           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
           //           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
           //           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP |
           0;
  if (!HasRspPubCert) {
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  }

  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof (Data32));

  Data8 = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
  SpdmSetData (SpdmContext, SpdmDataMeasurementSpec, &Parameter, &Data8, sizeof (Data8));
  Data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
           SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
           SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
           SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
           SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
           SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
  SpdmSetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, sizeof (Data32));
  Data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
           SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
           SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512;
  SpdmSetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, sizeof (Data32));
  Data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
           SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
           SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
  SpdmSetData (SpdmContext, SpdmDataDHENamedGroup, &Parameter, &Data16, sizeof (Data16));
  Data16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
           SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
           SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
  SpdmSetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &Data16, sizeof (Data16));
  Data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
  SpdmSetData (SpdmContext, SpdmDataKeySchedule, &Parameter, &Data16, sizeof (Data16));
  Data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
  SpdmSetData (SpdmContext, SpdmDataOtherParamsSsupport, &Parameter, &Data8, sizeof (Data8));
  IsRequrester = TRUE;
  SpdmReturn = SpdmSetData (SpdmContext, LIBSPDM_DATA_IS_REQUESTER, &Parameter, &IsRequrester, sizeof (IsRequrester));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    goto Error;
  }

  SpdmReturn = SpdmInitConnection (SpdmContext, FALSE);
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    DEBUG ((DEBUG_ERROR, "SpdmInitConnection - %p\n", SpdmReturn));
    goto Error;
  }
  */

  return SpdmDriverContext;
  /*
Error:
  FreePool (SpdmDriverContext);
  return NULL;
  */
}

/**

  Device probe function for this driver.

  The DXE core calls this function for any given device in order to see if the
  driver can drive the device.

  Specs relevant in the general sense:

  - UEFI Spec 2.3.1 + Errata C:
    - 6.3 Protocol Handler Services -- for accessing the underlying device
    - 10.1 EFI Driver Binding Protocol -- for exporting ourselves

  - Driver Writer's Guide for UEFI 2.3.1 v1.01:
    - 5.1.3.4 OpenProtocol() and CloseProtocol() -- for accessing the
      underlying device
    - 9 Driver Binding Protocol -- for exporting ourselves

  @param[in]  This                The EFI_DRIVER_BINDING_PROTOCOL object
                                  incorporating this driver (independently of
                                  any device).

  @param[in] DeviceHandle         The device to probe.

  @param[in] RemainingDevicePath  Relevant only for bus drivers, ignored.


  @retval EFI_SUCCESS      The driver supports the device being probed.

  @retval EFI_UNSUPPORTED  Based on virtio-blk discovery, we do not support
                           the device.

  @return                  Error codes from the OpenProtocol() boot service or
                           the VirtIo protocol.

**/
EFI_STATUS
EFIAPI
VirtioBlkDriverBindingSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   DeviceHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
  )
{
  EFI_STATUS              Status;
  VIRTIO_DEVICE_PROTOCOL  *VirtIo;

  //
  // Attempt to open the device with the VirtIo set of interfaces. On success,
  // the protocol is "instantiated" for the VirtIo device. Covers duplicate
  // open attempts (EFI_ALREADY_STARTED).
  //
  Status = gBS->OpenProtocol (
                  DeviceHandle,               // candidate device
                  &gVirtioDeviceProtocolGuid, // for generic VirtIo access
                  (VOID **)&VirtIo,           // handle to instantiate
                  This->DriverBindingHandle,  // requestor driver identity
                  DeviceHandle,               // ControllerHandle, according to
                                              // the UEFI Driver Model
                  EFI_OPEN_PROTOCOL_BY_DRIVER // get exclusive VirtIo access to
                                              // the device; to be released
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (VirtIo->SubSystemDeviceId != VIRTIO_SUBSYSTEM_BLOCK_DEVICE) {
    Status = EFI_UNSUPPORTED;
  }

  //
  // We needed VirtIo access only transitorily, to see whether we support the
  // device or not.
  //
  gBS->CloseProtocol (
         DeviceHandle,
         &gVirtioDeviceProtocolGuid,
         This->DriverBindingHandle,
         DeviceHandle
         );
  return Status;
}

/**

  Set up all BlockIo and virtio-blk aspects of this driver for the specified
  device.

  @param[in out] Dev  The driver instance to configure. The caller is
                      responsible for Dev->VirtIo's validity (ie. working IO
                      access to the underlying virtio-blk device).

  @retval EFI_SUCCESS      Setup complete.

  @retval EFI_UNSUPPORTED  The driver is unable to work with the virtio ring or
                           virtio-blk attributes the host provides.

  @return                  Error codes from VirtioRingInit() or
                           VIRTIO_CFG_READ() / VIRTIO_CFG_WRITE or
                           VirtioRingMap().

**/
STATIC
EFI_STATUS
EFIAPI
VirtioBlkInit (
  IN OUT VBLK_DEV  *Dev
  )
{
  UINT8       NextDevStat;
  EFI_STATUS  Status;

  UINT64  Features;
  UINT64  NumSectors;
  UINT32  BlockSize;
  UINT8   PhysicalBlockExp;
  UINT8   AlignmentOffset;
  UINT32  OptIoSize;
  UINT16  QueueSize;
  UINT64  RingBaseShift;

  PhysicalBlockExp = 0;
  AlignmentOffset  = 0;
  OptIoSize        = 0;

  //
  // Execute virtio-0.9.5, 2.2.1 Device Initialization Sequence.
  //
  NextDevStat = 0;             // step 1 -- reset device
  Status      = Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, NextDevStat);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  NextDevStat |= VSTAT_ACK;    // step 2 -- acknowledge device presence
  Status       = Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, NextDevStat);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  NextDevStat |= VSTAT_DRIVER; // step 3 -- we know how to drive it
  Status       = Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, NextDevStat);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  //
  // Set Page Size - MMIO VirtIo Specific
  //
  Status = Dev->VirtIo->SetPageSize (Dev->VirtIo, EFI_PAGE_SIZE);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  //
  // step 4a -- retrieve and validate features
  //
  Status = Dev->VirtIo->GetDeviceFeatures (Dev->VirtIo, &Features);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  Status = VIRTIO_CFG_READ (Dev, Capacity, &NumSectors);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  if (NumSectors == 0) {
    Status = EFI_UNSUPPORTED;
    goto Failed;
  }

  if (Features & VIRTIO_BLK_F_BLK_SIZE) {
    Status = VIRTIO_CFG_READ (Dev, BlkSize, &BlockSize);
    if (EFI_ERROR (Status)) {
      goto Failed;
    }

    if ((BlockSize == 0) || (BlockSize % 512 != 0) ||
        (ModU64x32 (NumSectors, BlockSize / 512) != 0))
    {
      //
      // We can only handle a logical block consisting of whole sectors,
      // and only a disk composed of whole logical blocks.
      //
      Status = EFI_UNSUPPORTED;
      goto Failed;
    }
  } else {
    BlockSize = 512;
  }

  if (Features & VIRTIO_BLK_F_TOPOLOGY) {
    Status = VIRTIO_CFG_READ (
               Dev,
               Topology.PhysicalBlockExp,
               &PhysicalBlockExp
               );
    if (EFI_ERROR (Status)) {
      goto Failed;
    }

    if (PhysicalBlockExp >= 32) {
      Status = EFI_UNSUPPORTED;
      goto Failed;
    }

    Status = VIRTIO_CFG_READ (Dev, Topology.AlignmentOffset, &AlignmentOffset);
    if (EFI_ERROR (Status)) {
      goto Failed;
    }

    Status = VIRTIO_CFG_READ (Dev, Topology.OptIoSize, &OptIoSize);
    if (EFI_ERROR (Status)) {
      goto Failed;
    }
  }

  Features &= VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_TOPOLOGY | VIRTIO_BLK_F_RO |
              VIRTIO_BLK_F_FLUSH | VIRTIO_F_VERSION_1 |
              VIRTIO_F_IOMMU_PLATFORM;

  //
  // In virtio-1.0, feature negotiation is expected to complete before queue
  // discovery, and the device can also reject the selected set of features.
  //
  if (Dev->VirtIo->Revision >= VIRTIO_SPEC_REVISION (1, 0, 0)) {
    Status = Virtio10WriteFeatures (Dev->VirtIo, Features, &NextDevStat);
    if (EFI_ERROR (Status)) {
      goto Failed;
    }
  }

  //
  // step 4b -- allocate virtqueue
  //
  Status = Dev->VirtIo->SetQueueSel (Dev->VirtIo, 0);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  Status = Dev->VirtIo->GetQueueNumMax (Dev->VirtIo, &QueueSize);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  if (QueueSize < 3) {
    // SynchronousRequest() uses at most three descriptors
    Status = EFI_UNSUPPORTED;
    goto Failed;
  }

  Status = VirtioRingInit (Dev->VirtIo, QueueSize, &Dev->Ring);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  //
  // If anything fails from here on, we must release the ring resources
  //
  Status = VirtioRingMap (
             Dev->VirtIo,
             &Dev->Ring,
             &RingBaseShift,
             &Dev->RingMap
             );
  if (EFI_ERROR (Status)) {
    goto ReleaseQueue;
  }

  //
  // Additional steps for MMIO: align the queue appropriately, and set the
  // size. If anything fails from here on, we must unmap the ring resources.
  //
  Status = Dev->VirtIo->SetQueueNum (Dev->VirtIo, QueueSize);
  if (EFI_ERROR (Status)) {
    goto UnmapQueue;
  }

  Status = Dev->VirtIo->SetQueueAlign (Dev->VirtIo, EFI_PAGE_SIZE);
  if (EFI_ERROR (Status)) {
    goto UnmapQueue;
  }

  //
  // step 4c -- Report GPFN (guest-physical frame number) of queue.
  //
  Status = Dev->VirtIo->SetQueueAddress (
                          Dev->VirtIo,
                          &Dev->Ring,
                          RingBaseShift
                          );
  if (EFI_ERROR (Status)) {
    goto UnmapQueue;
  }

  //
  // step 5 -- Report understood features.
  //
  if (Dev->VirtIo->Revision < VIRTIO_SPEC_REVISION (1, 0, 0)) {
    Features &= ~(UINT64)(VIRTIO_F_VERSION_1 | VIRTIO_F_IOMMU_PLATFORM);
    Status    = Dev->VirtIo->SetGuestFeatures (Dev->VirtIo, Features);
    if (EFI_ERROR (Status)) {
      goto UnmapQueue;
    }
  }

  //
  // step 6 -- initialization complete
  //
  NextDevStat |= VSTAT_DRIVER_OK;
  Status       = Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, NextDevStat);
  if (EFI_ERROR (Status)) {
    goto UnmapQueue;
  }

  //
  // Populate the exported interface's attributes; see UEFI spec v2.4, 12.9 EFI
  // Block I/O Protocol.
  //
  Dev->BlockIo.Revision              = 0;
  Dev->BlockIo.Media                 = &Dev->BlockIoMedia;
  Dev->BlockIo.Reset                 = &VirtioBlkReset;
  Dev->BlockIo.ReadBlocks            = &VirtioBlkReadBlocks;
  Dev->BlockIo.WriteBlocks           = &VirtioBlkWriteBlocks;
  Dev->BlockIo.FlushBlocks           = &VirtioBlkFlushBlocks;
  Dev->BlockIoMedia.MediaId          = 0;
  Dev->BlockIoMedia.RemovableMedia   = FALSE;
  Dev->BlockIoMedia.MediaPresent     = TRUE;
  Dev->BlockIoMedia.LogicalPartition = FALSE;
  Dev->BlockIoMedia.ReadOnly         = (BOOLEAN)((Features & VIRTIO_BLK_F_RO) != 0);
  Dev->BlockIoMedia.WriteCaching     = (BOOLEAN)((Features & VIRTIO_BLK_F_FLUSH) != 0);
  Dev->BlockIoMedia.BlockSize        = BlockSize;
  Dev->BlockIoMedia.IoAlign          = 0;
  Dev->BlockIoMedia.LastBlock        = DivU64x32 (
                                         NumSectors,
                                         BlockSize / 512
                                         ) - 1;

  DEBUG ((
    DEBUG_INFO,
    "%a: LbaSize=0x%x[B] NumBlocks=0x%Lx[Lba]\n",
    __func__,
    Dev->BlockIoMedia.BlockSize,
    Dev->BlockIoMedia.LastBlock + 1
    ));

  if (Features & VIRTIO_BLK_F_TOPOLOGY) {
    Dev->BlockIo.Revision = EFI_BLOCK_IO_PROTOCOL_REVISION3;

    Dev->BlockIoMedia.LowestAlignedLba                 = AlignmentOffset;
    Dev->BlockIoMedia.LogicalBlocksPerPhysicalBlock    = 1u << PhysicalBlockExp;
    Dev->BlockIoMedia.OptimalTransferLengthGranularity = OptIoSize;

    DEBUG ((
      DEBUG_INFO,
      "%a: FirstAligned=0x%Lx[Lba] PhysBlkSize=0x%x[Lba]\n",
      __func__,
      Dev->BlockIoMedia.LowestAlignedLba,
      Dev->BlockIoMedia.LogicalBlocksPerPhysicalBlock
      ));
    DEBUG ((
      DEBUG_INFO,
      "%a: OptimalTransferLengthGranularity=0x%x[Lba]\n",
      __func__,
      Dev->BlockIoMedia.OptimalTransferLengthGranularity
      ));
  }

  return EFI_SUCCESS;

UnmapQueue:
  Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, Dev->RingMap);

ReleaseQueue:
  VirtioRingUninit (Dev->VirtIo, &Dev->Ring);

Failed:
  //
  // Notify the host about our failure to setup: virtio-0.9.5, 2.2.2.1 Device
  // Status. VirtIo access failure here should not mask the original error.
  //
  NextDevStat |= VSTAT_FAILED;
  Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, NextDevStat);

  return Status; // reached only via Failed above
}

/**

  Uninitialize the internals of a virtio-blk device that has been successfully
  set up with VirtioBlkInit().

  @param[in out]  Dev  The device to clean up.

**/
STATIC
VOID
EFIAPI
VirtioBlkUninit (
  IN OUT VBLK_DEV  *Dev
  )
{
  //
  // Reset the virtual device -- see virtio-0.9.5, 2.2.2.1 Device Status. When
  // VIRTIO_CFG_WRITE() returns, the host will have learned to stay away from
  // the old comms area.
  //
  Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, 0);

  Dev->VirtIo->UnmapSharedBuffer (Dev->VirtIo, Dev->RingMap);
  VirtioRingUninit (Dev->VirtIo, &Dev->Ring);

  SetMem (&Dev->BlockIo, sizeof Dev->BlockIo, 0x00);
  SetMem (&Dev->BlockIoMedia, sizeof Dev->BlockIoMedia, 0x00);
}

/**

  Event notification function enqueued by ExitBootServices().

  @param[in] Event    Event whose notification function is being invoked.

  @param[in] Context  Pointer to the VBLK_DEV structure.

**/
STATIC
VOID
EFIAPI
VirtioBlkExitBoot (
  IN  EFI_EVENT  Event,
  IN  VOID       *Context
  )
{
  VBLK_DEV  *Dev;

  DEBUG ((DEBUG_VERBOSE, "%a: Context=0x%p\n", __func__, Context));
  //
  // Reset the device. This causes the hypervisor to forget about the virtio
  // ring.
  //
  // We allocated said ring in EfiBootServicesData type memory, and code
  // executing after ExitBootServices() is permitted to overwrite it.
  //
  Dev = Context;
  Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, 0);
}

/**

  After we've pronounced support for a specific device in
  DriverBindingSupported(), we start managing said device (passed in by the
  Driver Execution Environment) with the following service.

  See DriverBindingSupported() for specification references.

  @param[in]  This                The EFI_DRIVER_BINDING_PROTOCOL object
                                  incorporating this driver (independently of
                                  any device).

  @param[in] DeviceHandle         The supported device to drive.

  @param[in] RemainingDevicePath  Relevant only for bus drivers, ignored.


  @retval EFI_SUCCESS           Driver instance has been created and
                                initialized  for the virtio-blk device, it
                                is now accessible via EFI_BLOCK_IO_PROTOCOL.

  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.

  @return                       Error codes from the OpenProtocol() boot
                                service, the VirtIo protocol, VirtioBlkInit(),
                                or the InstallProtocolInterface() boot service.

**/
EFI_STATUS
EFIAPI
VirtioBlkDriverBindingStart (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   DeviceHandle,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
  )
{
  VBLK_DEV    *Dev;
  EFI_STATUS  Status;

  Dev = (VBLK_DEV *)AllocateZeroPool (sizeof *Dev);
  if (Dev == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gBS->OpenProtocol (
                  DeviceHandle,
                  &gVirtioDeviceProtocolGuid,
                  (VOID **)&Dev->VirtIo,
                  This->DriverBindingHandle,
                  DeviceHandle,
                  EFI_OPEN_PROTOCOL_BY_DRIVER
                  );
  if (EFI_ERROR (Status)) {
    goto FreeVirtioBlk;
  }

  //
  // VirtIo access granted, configure virtio-blk device.
  //
  Status = VirtioBlkInit (Dev);
  if (EFI_ERROR (Status)) {
    goto CloseVirtIo;
  }

  Status = gBS->CreateEvent (
                  EVT_SIGNAL_EXIT_BOOT_SERVICES,
                  TPL_CALLBACK,
                  &VirtioBlkExitBoot,
                  Dev,
                  &Dev->ExitBoot
                  );
  if (EFI_ERROR (Status)) {
    goto UninitDev;
  }

  //
  // Setup complete, attempt to export the driver instance's BlockIo interface.
  //
  Dev->Signature = VBLK_SIG;
  Status         = gBS->InstallProtocolInterface (
                          &DeviceHandle,
                          &gEfiBlockIoProtocolGuid,
                          EFI_NATIVE_INTERFACE,
                          &Dev->BlockIo
                          );
  if (EFI_ERROR (Status)) {
    goto CloseExitBoot;
  }

  return EFI_SUCCESS;

CloseExitBoot:
  gBS->CloseEvent (Dev->ExitBoot);

UninitDev:
  VirtioBlkUninit (Dev);

CloseVirtIo:
  gBS->CloseProtocol (
         DeviceHandle,
         &gVirtioDeviceProtocolGuid,
         This->DriverBindingHandle,
         DeviceHandle
         );

FreeVirtioBlk:
  FreePool (Dev);

  return Status;
}

/**

  Stop driving a virtio-blk device and remove its BlockIo interface.

  This function replays the success path of DriverBindingStart() in reverse.
  The host side virtio-blk device is reset, so that the OS boot loader or the
  OS may reinitialize it.

  @param[in] This               The EFI_DRIVER_BINDING_PROTOCOL object
                                incorporating this driver (independently of any
                                device).

  @param[in] DeviceHandle       Stop driving this device.

  @param[in] NumberOfChildren   Since this function belongs to a device driver
                                only (as opposed to a bus driver), the caller
                                environment sets NumberOfChildren to zero, and
                                we ignore it.

  @param[in] ChildHandleBuffer  Ignored (corresponding to NumberOfChildren).

**/
EFI_STATUS
EFIAPI
VirtioBlkDriverBindingStop (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   DeviceHandle,
  IN UINTN                        NumberOfChildren,
  IN EFI_HANDLE                   *ChildHandleBuffer
  )
{
  EFI_STATUS             Status;
  EFI_BLOCK_IO_PROTOCOL  *BlockIo;
  VBLK_DEV               *Dev;

  Status = gBS->OpenProtocol (
                  DeviceHandle,                  // candidate device
                  &gEfiBlockIoProtocolGuid,      // retrieve the BlockIo iface
                  (VOID **)&BlockIo,             // target pointer
                  This->DriverBindingHandle,     // requestor driver identity
                  DeviceHandle,                  // requesting lookup for dev.
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL // lookup only, no ref. added
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Dev = VIRTIO_BLK_FROM_BLOCK_IO (BlockIo);

  //
  // Handle Stop() requests for in-use driver instances gracefully.
  //
  Status = gBS->UninstallProtocolInterface (
                  DeviceHandle,
                  &gEfiBlockIoProtocolGuid,
                  &Dev->BlockIo
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  gBS->CloseEvent (Dev->ExitBoot);

  VirtioBlkUninit (Dev);

  gBS->CloseProtocol (
         DeviceHandle,
         &gVirtioDeviceProtocolGuid,
         This->DriverBindingHandle,
         DeviceHandle
         );

  FreePool (Dev);

  return EFI_SUCCESS;
}

//
// The static object that groups the Supported() (ie. probe), Start() and
// Stop() functions of the driver together. Refer to UEFI Spec 2.3.1 + Errata
// C, 10.1 EFI Driver Binding Protocol.
//
STATIC EFI_DRIVER_BINDING_PROTOCOL  gDriverBinding = {
  &VirtioBlkDriverBindingSupported,
  &VirtioBlkDriverBindingStart,
  &VirtioBlkDriverBindingStop,
  0x10, // Version, must be in [0x10 .. 0xFFFFFFEF] for IHV-developed drivers
  NULL, // ImageHandle, to be overwritten by
        // EfiLibInstallDriverBindingComponentName2() in VirtioBlkEntryPoint()
  NULL  // DriverBindingHandle, ditto
};

//
// The purpose of the following scaffolding (EFI_COMPONENT_NAME_PROTOCOL and
// EFI_COMPONENT_NAME2_PROTOCOL implementation) is to format the driver's name
// in English, for display on standard console devices. This is recommended for
// UEFI drivers that follow the UEFI Driver Model. Refer to the Driver Writer's
// Guide for UEFI 2.3.1 v1.01, 11 UEFI Driver and Controller Names.
//
// Device type names ("Virtio Block Device") are not formatted because the
// driver supports only that device type. Therefore the driver name suffices
// for unambiguous identification.
//

STATIC
EFI_UNICODE_STRING_TABLE  mDriverNameTable[] = {
  { "eng;en", L"Virtio Block Driver" },
  { NULL,     NULL                   }
};

STATIC
EFI_COMPONENT_NAME_PROTOCOL  gComponentName;

EFI_STATUS
EFIAPI
VirtioBlkGetDriverName (
  IN  EFI_COMPONENT_NAME_PROTOCOL  *This,
  IN  CHAR8                        *Language,
  OUT CHAR16                       **DriverName
  )
{
  return LookupUnicodeString2 (
           Language,
           This->SupportedLanguages,
           mDriverNameTable,
           DriverName,
           (BOOLEAN)(This == &gComponentName) // Iso639Language
           );
}

EFI_STATUS
EFIAPI
VirtioBlkGetDeviceName (
  IN  EFI_COMPONENT_NAME_PROTOCOL  *This,
  IN  EFI_HANDLE                   DeviceHandle,
  IN  EFI_HANDLE                   ChildHandle,
  IN  CHAR8                        *Language,
  OUT CHAR16                       **ControllerName
  )
{
  return EFI_UNSUPPORTED;
}

STATIC
EFI_COMPONENT_NAME_PROTOCOL  gComponentName = {
  &VirtioBlkGetDriverName,
  &VirtioBlkGetDeviceName,
  "eng" // SupportedLanguages, ISO 639-2 language codes
};

STATIC
EFI_COMPONENT_NAME2_PROTOCOL  gComponentName2 = {
  (EFI_COMPONENT_NAME2_GET_DRIVER_NAME)&VirtioBlkGetDriverName,
  (EFI_COMPONENT_NAME2_GET_CONTROLLER_NAME)&VirtioBlkGetDeviceName,
  "en" // SupportedLanguages, RFC 4646 language codes
};

//
// Entry point of this driver.
//
EFI_STATUS
EFIAPI
VirtioBlkEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return EfiLibInstallDriverBindingComponentName2 (
           ImageHandle,
           SystemTable,
           &gDriverBinding,
           ImageHandle,
           &gComponentName,
           &gComponentName2
           );
}
