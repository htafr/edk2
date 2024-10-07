#include "SpdmDeviceSecurityDxe.h"

#define SPDM_TIMEOUT  1000000   /* 1 second */

/*
VOID
PcieDoeControlRead32 (
  IN      EFI_PCI_IO_PROTOCOL *This,
  IN OUT  UINT32              *Buffer
  )
{
  This->PciIo->Pci.Read (
                    This->PciIo,
                    EfiPciIoWidthUint32,
                    This->DoeCapabilityOffset + PCI_EXPRESS_REG_DOE_CONTROL_OFFSET,
                    1,
                    Buffer
                    );
}

VOID
PcieDoeControlWrite32 (
  IN      EFI_PCI_IO_PROTOCOL *This,
  IN      UINT32              *Buffer
  )
{
  This->PciIo->Pci.Write (
                    This->PciIo,
                    EfiPciIoWidthUint32,
                    This->DoeCapabilityOffset + PCI_EXPRESS_REG_DOE_CONTROL_OFFSET,
                    1,
                    Buffer
                    );
}

VOID
PcieDoeStatusRead32 (
  IN      SPDM_PRIVATE_DATA *This,
  IN OUT  UINT32            *Buffer
  )
{
  This->PciIo->Pci.Read (
                    This->PciIo,
                    EfiPciIoWidthUint32,
                    This->DoeCapabilityOffset + PCI_EXPRESS_REG_DOE_STATUS_OFFSET,
                    1,
                    Buffer
                    );
}

VOID
PcieDoeWriteMailboxWrite32 (
  IN     SPDM_PRIVATE_DATA  *This,
  IN     UINT32             *Buffer
  )
{
  This->PciIo->Pci.Write (
                        This->PciIo,
                        EfiPciIoWidthUint32,
                        This->DoeCapabilityOffset + PCI_EXPRESS_REG_DOE_WRITE_DATA_MAILBOX_OFFSET,
                        1,
                        Buffer
                        );
  return;
}

VOID
PcieDoeReadMailboxRead32 (
  IN     SPDM_PRIVATE_DATA  *This,
  IN OUT UINT32             *Buffer
  )
{
  This->PciIo->Pci.Read (
                        This->PciIo,
                        EfiPciIoWidthUint32,
                        This->DoeCapabilityOffset + PCI_EXPRESS_REG_DOE_READ_DATA_MAILBOX_OFFSET,
                        1,
                        Buffer
                        );
  return;
}

VOID
PcieDoeReadMailboxWrite32 (
  IN     SPDM_PRIVATE_DATA  *This,
  IN     UINT32             *Buffer
  )
{
  This->PciIo->Pci.Write (
                        This->PciIo,
                        EfiPciIoWidthUint32,
                        This->DoeCapabilityOffset + PCI_EXPRESS_REG_DOE_READ_DATA_MAILBOX_OFFSET,
                        1,
                        Buffer
                        );
  return;
}
//*/

SPDM_RETURN
SpdmIoSendRequest (
  IN  SPDM_IO_PROTOCOL  *This,
  IN  UINTN             RequestSize,
  IN  CONST VOID        *Request,
  IN  UINT64            Timeout
  )
{
  EFI_STATUS                  Status;
  EFI_HANDLE                  Handle;
  UINTN                       BufferSize;
  EDKII_PCI_DOE_PROTOCOL      *PciDoeProtocol;
  //UINT64                      Delay = 0;
  UINT32                      DataObjectSize;
  UINT8                       *DataObjectBuffer;

  if (Request == NULL) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  if (RequestSize == 0) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  BufferSize = sizeof (Handle);
  Status     = gBS->LocateHandle (
                      ByProtocol,
                      &gEdkiiPciDoeProtocol,
                      NULL,
                      &BufferSize,
                      &Handle
                      );
  ASSERT_EFI_ERROR (Status);

  Status = gBS->HandleProtocol (
                  Handle,
                  &gEdkiiPciDoeProtocol,
                  (VOID **)&PciDoeProtocol
                  );
  ASSERT_EFI_ERROR (Status);

  DataObjectSize   = (UINT32)RequestSize;
  DataObjectBuffer = (UINT8 *)Request;

  if (Timeout == 0) {
    Timeout = SPDM_TIMEOUT;
  }

  //Delay = DivU64x32 (Timeout, 30) + 1;

  /*
   *
   * TODO: Implement Timeout
   */
  /*
  do {
    if (Status == EFI_SUCCESS) {
      break;
    } else {
      gBS->Stall (30); // Stall for 30 microseconds
      Delay--;
    }
  } while (Delay != 0);

  if (Delay == 0) {
    Status = LIBSPDM_STATUS_SEND_FAIL;
  } else {
    Status = LIBSPDM_STATUS_SUCCESS;
  }
  //*/
  Status = PciDoeProtocol->Send (PciDoeProtocol, DataObjectSize, DataObjectBuffer);
  if (EFI_ERROR (Status)) {
    return LIBSPDM_STATUS_SEND_FAIL;
  } else {
    return LIBSPDM_STATUS_SUCCESS;
  }
}

SPDM_RETURN
SpdmIoReceiveResponse (
  IN     SPDM_IO_PROTOCOL  *This,
  IN OUT UINTN             *ResponseSize,
  IN OUT VOID              **Response,
  IN     UINT64            Timeout
  )
{
  EFI_STATUS                  Status;
  EFI_HANDLE                  Handle;
  UINTN                       BufferSize;
  EDKII_PCI_DOE_PROTOCOL      *PciDoeProtocol;
  UINT8                       *ResponseDataObjectBuffer = NULL;
  UINTN                       ResponseDataObjectSize    = 0;
  UINTN                       DataObjectSize            = 0;
  //UINT64                      Delay  = 0;

  DEBUG ((DEBUG_ERROR, "[%a] Start ... \n", __func__));

  if (*Response == NULL) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  if (ResponseSize == NULL) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  BufferSize = sizeof (Handle);
  Status     = gBS->LocateHandle (
                      ByProtocol,
                      &gEdkiiPciDoeProtocol,
                      NULL,
                      &BufferSize,
                      &Handle
                      );
  ASSERT_EFI_ERROR (Status);

  Status = gBS->HandleProtocol (
                  Handle,
                  &gEdkiiPciDoeProtocol,
                  (VOID **)&PciDoeProtocol
                  );
  ASSERT_EFI_ERROR (Status);


  if (Timeout == 0) {
    Timeout = SPDM_TIMEOUT;
  }

  //Delay = DivU64x32 (Timeout, 30) + 1;

  /**
    TODO: Check the logic with new PciDoeProtocol and implement timeout
  **/
  /* Poll the Data Object Ready bit
  do {

    PcieDoeStatusRead32 (SpdmPrivateData, &DoeStatus.Uint32);

    if (DoeStatus.Bits.DataObjectReady == 1) {
      DEBUG ((DEBUG_ERROR, "[%a] 'Data Object Ready' bit is set. Start reading Mailbox ...\n", __func__ ));

      // Get DataObjectHeader1
      PcieDoeReadMailboxRead32 (SpdmPrivateData, (UINT32 *)*Response);
      // Write to the DOE Read Data Mailbox to indicate a successful read
      PcieDoeReadMailboxWrite32 (SpdmPrivateData, &Data32);

      // Get DataObjectHeader2.
      PcieDoeReadMailboxRead32 (SpdmPrivateData, (UINT32 *)*Response + 1);
      // Write to the DOE Read Data Mailbox to indicate a successful read
      PcieDoeReadMailboxWrite32 (SpdmPrivateData, &Data32);

      DataObjectSize = DataObjectHeader->Length * sizeof (UINT32);
      DEBUG ((DEBUG_ERROR, "[%a] DataObjectSize = 0x%x\n", __func__, DataObjectSize));

      if (DataObjectSize > *ResponseSize) {
        *ResponseSize = DataObjectSize;
        return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
      }
    ResponseDataObjectSize   = DataObjectSize - sizeof (PCI_DOE_DATA_OBJECT_HEADER);
    ResponseDataObjectBuffer = (UINT8 *)*Response + sizeof (PCI_DOE_DATA_OBJECT_HEADER);
    Index                    = 0;
      do {
        // Read data from the DOE Read Data Mailbox and save it
        PcieDoeReadMailboxRead32 (SpdmPrivateData, (UINT32 *)(ResponseDataObjectBuffer + Index));
        Index += sizeof (UINT32);
        // Write to the DOE Read Data Mailbox to indicate a successful read
        PcieDoeReadMailboxWrite32 (SpdmPrivateData, &Data32);
      } while (Index < ResponseDataObjectSize);

      *ResponseSize = DataObjectSize;

      break;
    } else {
      // Stall for 30 microseconds
      DEBUG ((DEBUG_ERROR, "[%a] 'Data Object Ready' bit is not set! Waiting ...\n", __func__));
      gBS->Stall (30);
      Delay--;
    }
  } while (Delay != 0);
  //*/

  /* Get Headers */
  *ResponseSize = 2 * sizeof (UINT32);
  PciDoeProtocol->Receive (PciDoeProtocol, ResponseSize, *Response);

  /*
  DEBUG ((DEBUG_INFO, "[EDKII @ %a]: ", __func__));
  for (UINTN i = 0; i < *ResponseSize; i++)
    DEBUG ((DEBUG_INFO, "%02X ", ((UINT8 *)*Response)[i]));
  DEBUG ((DEBUG_INFO, "\n"));
  //*/

  DataObjectSize = *(UINTN *)(((UINT32 *)*Response) + 1);

  /**
    TODO: if the return of this function is an error, it's necessary
          to reset PCI DOE Mailbox
  **/
  if (DataObjectSize * sizeof (UINT32) > LIBSPDM_MAX_SPDM_MSG_SIZE) {
    *ResponseSize = DataObjectSize;
    return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
  }

  ResponseDataObjectSize   = (DataObjectSize - 2) * sizeof (UINT32);
  ResponseDataObjectBuffer = (UINT8 *)*Response + (2 * sizeof (UINT32));

  if (PciDoeProtocol->Receive (PciDoeProtocol, &ResponseDataObjectSize, (VOID *)ResponseDataObjectBuffer) != EFI_SUCCESS) {
    goto Error;
  }

  *ResponseSize = DataObjectSize * sizeof (UINT32);

  /*
  if (Delay == 0) {
    Status = LIBSPDM_STATUS_RECEIVE_FAIL;
  } else {
    Status = LIBSPDM_STATUS_SUCCESS;
  }
  DEBUG ((DEBUG_INFO, "[EDKII @ %a]: ", __func__));
  for (UINTN i = 0; i < *ResponseSize; i++)
    DEBUG ((DEBUG_INFO, "%02X ", ((UINT8 *)*Response)[i]));
  DEBUG ((DEBUG_INFO, "\n"));
  //*/

  return LIBSPDM_STATUS_SUCCESS;

Error:
  return LIBSPDM_STATUS_RECEIVE_FAIL;
}

SPDM_IO_PROTOCOL mSpdmIoProtocol = {
  SpdmIoSendRequest,
  SpdmIoReceiveResponse
};

EFI_STATUS
EFIAPI
InstallSpdmIoProtocol (
  EFI_HANDLE  *Handle
  )
{
  return gBS->InstallProtocolInterface (
                Handle,
                &gSpdmIoProtocolGuid,
                EFI_NATIVE_INTERFACE,
                (VOID **)&mSpdmIoProtocol
                );
}

EFI_STATUS
EFIAPI
UninstallSpdmIoProtocol (
  EFI_HANDLE *Handle
  )
{
  return gBS->UninstallProtocolInterface (
                *Handle,
                &gSpdmIoProtocolGuid,
                (VOID **)&mSpdmIoProtocol
                );
}
