#include "SpdmDeviceSecurityDxe.h"

#define SPDM_TIMEOUT  1000000   /* 1 second */

static
SPDM_DEVICE_BUS_TYPE
GetSpdmBusType (
  OUT EFI_HANDLE  *Handle
  )
{
  EFI_STATUS  Status;
  UINTN       BufferSize;

  ///
  /// Check which type of device it is
  ///
  BufferSize = sizeof (EFI_HANDLE);
  Status     = gBS->LocateHandle (
                      ByProtocol,
                      &gEdkiiDeviceIdentifierTypePciGuid,
                      NULL,
                      &BufferSize,
                      Handle
                      );
  if (!EFI_ERROR (Status)) {
    return SPDM_DEVICE_PCI_TYPE;
  }

  Status = gBS->LocateHandle (
                  ByProtocol,
                  &gEdkiiDeviceIdentifierTypeUsbGuid,
                  NULL,
                  &BufferSize,
                  Handle
                  );
  if (!EFI_ERROR (Status)) {
    return SPDM_DEVICE_USB_TYPE;
  }

  return SPDM_DEVICE_BUS_NONE;
}

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
  // UINTN                       BufferSize;
  EDKII_PCI_DOE_PROTOCOL      *PciDoeProtocol;
  EDKII_USB_SPDM_PROTOCOL     *UsbSpdm;
  //UINT64                      Delay = 0;
  UINT32                      DataObjectSize;
  UINT8                       *DataObjectBuffer;
  SPDM_DEVICE_BUS_TYPE        BusType;

  if (Request == NULL) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  if (RequestSize == 0) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  BusType = GetSpdmBusType (&Handle);

  if (BusType == SPDM_DEVICE_PCI_TYPE) {
    Status = gBS->HandleProtocol (
                    Handle,
                    &gEdkiiPciDoeProtocol,
                    (VOID **)&PciDoeProtocol
                    );
    ASSERT_EFI_ERROR (Status);
  } else if (BusType == SPDM_DEVICE_USB_TYPE) {
    Status = gBS->HandleProtocol (
                    Handle,
                    &gEdkiiUsbSpdmProtocolGuid,
                    (VOID **)&UsbSpdm
                    );
    ASSERT_EFI_ERROR (Status);
  }

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
  if (BusType == SPDM_DEVICE_PCI_TYPE) {
    Status = PciDoeProtocol->Send (PciDoeProtocol, DataObjectSize, DataObjectBuffer);
  } else if (BusType == SPDM_DEVICE_USB_TYPE) {
    Status = UsbSpdm->Send (UsbSpdm, DataObjectBuffer, DataObjectSize);
  }
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
  // UINTN                       BufferSize;
  EDKII_PCI_DOE_PROTOCOL      *PciDoeProtocol;
  EDKII_USB_SPDM_PROTOCOL     *UsbSpdm;
  UINT8                       *ResponseDataObjectBuffer = NULL;
  UINTN                       ResponseDataObjectSize    = 0;
  UINTN                       DataObjectSize            = 0;
  //UINT64                      Delay  = 0;
  SPDM_DEVICE_BUS_TYPE        BusType;

  DEBUG ((DEBUG_ERROR, "[%a] Start ... \n", __func__));

  if (*Response == NULL) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  if (ResponseSize == NULL) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  BusType = GetSpdmBusType (&Handle);

  if (BusType == SPDM_DEVICE_PCI_TYPE) {
    Status = gBS->HandleProtocol (
                    Handle,
                    &gEdkiiPciDoeProtocol,
                    (VOID **)&PciDoeProtocol
                    );
    ASSERT_EFI_ERROR (Status);
  } else if (BusType == SPDM_DEVICE_USB_TYPE) {
    Status = gBS->HandleProtocol (
                    Handle,
                    &gEdkiiUsbSpdmProtocolGuid,
                    (VOID **)&UsbSpdm
                    );
    ASSERT_EFI_ERROR (Status);
  }


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


  if (BusType == SPDM_DEVICE_PCI_TYPE) {
    /* Get Headers */
    *ResponseSize = 2 * sizeof (UINT32);
    PciDoeProtocol->Receive (PciDoeProtocol, ResponseSize, *Response);

    DataObjectSize = *(((UINT32 *)*Response) + 1);

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

    Status = PciDoeProtocol->Receive (PciDoeProtocol, &ResponseDataObjectSize, (VOID *)ResponseDataObjectBuffer);
    if (EFI_ERROR (Status)) {
      goto Error;
    }
    *ResponseSize = DataObjectSize * sizeof (UINT32);
  } else if (BusType == SPDM_DEVICE_USB_TYPE) {
    ResponseDataObjectSize = 2;
    ResponseDataObjectBuffer = AllocateZeroPool (LIBSPDM_MAX_SPDM_MSG_SIZE);
    Status = UsbSpdm->Receive (UsbSpdm, (UINT16)DataObjectSize, &ResponseDataObjectSize, (VOID *)ResponseDataObjectBuffer);
    if (EFI_ERROR (Status)) {
      goto Error;
    }

    ResponseDataObjectSize = 64;
    *ResponseSize = *ResponseDataObjectBuffer |
                    *(ResponseDataObjectBuffer + sizeof (UINT8)) << 8;
    ResponseDataObjectBuffer = (UINT8 *)*Response;
    do {
      Status = UsbSpdm->Receive (
                          UsbSpdm,
                          (UINT16)DataObjectSize,
                          &ResponseDataObjectSize,
                          (VOID *)(ResponseDataObjectBuffer + (DataObjectSize * sizeof (UINT8)))
                          );
      if (EFI_ERROR (Status)) {
        goto Error;
      }

      DataObjectSize += ResponseDataObjectSize;
    } while (DataObjectSize < *ResponseSize);

    *ResponseSize = *ResponseSize - 2;
    *Response = (UINT8 *)*Response + (2 * sizeof (UINT8));
  }

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
    DEBUG ((DEBUG_INFO, "\n\n\n[EDKII @ %a]: DeviceHandle - 0x%X\n\n\n\n", __func__, Handle));
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
