#ifndef EFI_USB_SPDM_H
#define EFI_USB_SPDM_H

#include <Protocol/UsbSpdm.h>

/**
  @param  This                    A pointer to the EDKII_USB_SPDM_PROTOCOL instance.
  @param  Data                    A pointer to the buffer of data that will be transmitted to USB
                                  device.
  @param  DataLength              The size, in bytes, of the data buffer specified by Data.

  @retval EFI_SUCCESS             The message was sent successfully.
  @retval EFI_DEVICE_ERROR        The message failed to be sent.
  @retval EFI_INVALID_PARAMETER   One or more parameters are invalid.
  @retval EFI_OUT_OF_RESOURCES    The request could not be submitted due to a lack of resources.

**/
EFI_STATUS
EFIAPI
UsbSpdmSend(
  IN EDKII_USB_SPDM_PROTOCOL  *This,
  IN OUT VOID                 *Data,
  IN OUT UINTN                *DataLength
  );

/**
  @param  This                    A pointer to the EDKII_USB_SPDM_PROTOCOL instance.
  @param  Data                    A pointer to the buffer of data that will be receveid from USB
                                  device.
  @param  DataLength              The number of bytes that were actually transferred.

  @retval EFI_SUCCESS             The message was received successfully.
  @retval EFI_DEVICE_ERROR        The message failed to be received.
  @retval EFI_INVALID_PARAMETER   One or more parameters are invalid.
  @retval EFI_OUT_OF_RESOURCES    The request could not be submitted due to a lack of resources.

**/
EFI_STATUS
EFIAPI
UsbSpdmReceive(
  IN EDKII_USB_SPDM_PROTOCOL  *This,
  IN OUT VOID                 *Data,
  IN OUT UINTN                *DataLength
  );

#endif
