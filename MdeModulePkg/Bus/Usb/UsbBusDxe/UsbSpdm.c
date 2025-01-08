#include "UsbBus.h"

EFI_STATUS
EFIAPI
UsbSpdmSend (
  IN EDKII_USB_SPDM_PROTOCOL  *This,
  IN VOID                     *Data,
  IN UINTN                    DataLength
  )
{
  USB_INTERFACE          *UsbIf;
  USB_DEVICE             *UsbDev;
  EFI_USB_DEVICE_REQUEST Request;
  EFI_STATUS             Status;
  UINT32                 TransStatus;

  UsbIf     = USB_INTERFACE_FROM_USB_SPDM (This);
  UsbDev    = UsbIf->Device;

  Request.RequestType = 0;
  Request.Request     = USB_REQ_SPDM;
  Request.Value       = 0;
  Request.Index       = 0;
  Request.Length      = (UINT16)DataLength;

  Status = UsbHcControlTransfer (
            UsbDev->Bus,
            UsbDev->Address,
            UsbDev->Speed,
            UsbDev->MaxPacket0,
            &Request,
            EfiUsbDataOut,
            Data,
            &DataLength,
            USB_GENERAL_DEVICE_REQUEST_TIMEOUT,
            &UsbDev->Translator,
            &TransStatus
            );

  return Status;
}

EFI_STATUS
EFIAPI
UsbSpdmReceive (
  IN  EDKII_USB_SPDM_PROTOCOL   *This,
  IN  UINT16                    Value,
  OUT UINTN                     *DataLength,
  OUT VOID                      *Data
  )
{
  USB_INTERFACE          *UsbIf;
  USB_DEVICE             *UsbDev;
  EFI_USB_DEVICE_REQUEST Request;
  EFI_STATUS             Status;
  UINT32                 TransStatus;

  UsbIf     = USB_INTERFACE_FROM_USB_SPDM (This);
  UsbDev    = UsbIf->Device;

  Request.RequestType = 0x80;
  Request.Request     = USB_REQ_SPDM;
  Request.Value       = Value;
  Request.Index       = 0;
  Request.Length      = *((UINT16 *)DataLength);

  Status = UsbHcControlTransfer (
            UsbDev->Bus,
            UsbDev->Address,
            UsbDev->Speed,
            UsbDev->MaxPacket0,
            &Request,
            EfiUsbDataIn,
            Data,
            DataLength,
            USB_GENERAL_DEVICE_REQUEST_TIMEOUT,
            &UsbDev->Translator,
            &TransStatus
            );
  return Status;
}

EDKII_USB_SPDM_PROTOCOL mUsbSpdmProtocol = {
  UsbSpdmSend,
  UsbSpdmReceive
};
