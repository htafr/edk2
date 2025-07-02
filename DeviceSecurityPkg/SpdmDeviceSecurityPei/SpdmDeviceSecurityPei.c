#include "SpdmDeviceSecurityPei.h"

EDKII_DEVICE_SECURITY_POLICY           mDeviceSecurityPolicyNone = {
  EDKII_DEVICE_SECURITY_POLICY_REVISION,
  0,
  0,
};

EDKII_DEVICE_SECURITY_POLICY           mDeviceSecurityPolicyFull = {
  EDKII_DEVICE_SECURITY_POLICY_REVISION,
  EDKII_DEVICE_MEASUREMENT_REQUIRED,
  EDKII_DEVICE_AUTHENTICATION_REQUIRED
};

/**
  This function returns the device security policy associated with the device.

  The device security driver may call this interface to get the platform policy
  for the specific device and determine if the measurement or authentication
  is required.

  @param[in]  This                   The protocol instance pointer.
  @param[in]  DeviceId               The Identifier for the device.
  @param[out] DeviceSecurityPolicy   The Device Security Policy associated with the device.

  @retval EFI_SUCCESS                The device security policy is returned
  @retval EFI_UNSUPPORTED            The function is unsupported for the specific Device.
**/
EFI_STATUS
EFIAPI
GetDevicePolicy (
  IN  EDKII_DEVICE_SECURITY_POLICY_PPI       *This,
  IN  EDKII_DEVICE_IDENTIFIER                *DeviceId,
  OUT EDKII_DEVICE_SECURITY_POLICY           *DeviceSecurityPolicy
  )
{
  CopyMem (DeviceSecurityPolicy, &mDeviceSecurityPolicyFull, sizeof(EDKII_DEVICE_SECURITY_POLICY));

  return EFI_SUCCESS;
}

/**
  This function sets the device state based upon the authentication result.

  The device security driver may call this interface to give the platform
  a notify based upon the measurement or authentication result.
  If the authentication or measurement fails, the platform may choose:
  1) Do nothing.
  2) Disable this device or slot temporarily and continue boot.
  3) Reset the platform and retry again.
  4) Disable this device or slot permanently.
  5) Any other platform specific action.

  @param[in]  This                   The protocol instance pointer.
  @param[in]  DeviceId               The Identifier for the device.
  @param[in]  DeviceSecurityState    The Device Security state associated with the device.

  @retval EFI_SUCCESS                The device state is set
  @retval EFI_UNSUPPORTED            The function is unsupported for the specific Device.
**/
EFI_STATUS
EFIAPI
NotifyDeviceState (
  IN  EDKII_DEVICE_SECURITY_POLICY_PPI       *This,
  IN  EDKII_DEVICE_IDENTIFIER                *DeviceId,
  IN  EDKII_DEVICE_SECURITY_STATE            *DeviceSecurityState
  )
{
  DEBUG ((DEBUG_INFO, "State - Measurement - 0x%08x, Authentication - 0x%08x\n",
    DeviceSecurityState->MeasurementState,
    DeviceSecurityState->AuthenticationState
    ));

  return EFI_SUCCESS;
}

EDKII_DEVICE_SECURITY_POLICY_PPI mDeviceSecurityPolicyPpi = {
  EDKII_DEVICE_SECURITY_POLICY_PPI_REVISION,
  GetDevicePolicy,
  NotifyDeviceState
};

EFI_PEI_PPI_DESCRIPTOR  mDeviceSecurityPolicyPpiList = {
  EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST,
  &gEdkiiDeviceSecurityPolicyPpiGuid,
  &mDeviceSecurityPolicyPpi
};

/**
  The device driver uses this service to measure and/or verify a device.

  The flow in device driver is:
  1) Device driver discovers a new device.
  2) Device driver creates an EFI_DEVICE_PATH_PROTOCOL.
  3) Device driver creates a device access protocol. e.g.
     EFI_PCI_IO_PROTOCOL for PCI device.
     EFI_USB_IO_PROTOCOL for USB device.
     EFI_EXT_SCSI_PASS_THRU_PROTOCOL for SCSI device.
     EFI_ATA_PASS_THRU_PROTOCOL for ATA device.
     EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL for NVMe device.
     EFI_SD_MMC_PASS_THRU_PROTOCOL for SD/MMC device.
     The device driver also creates the SPDM_IO_PROTOCOL.
  4) Device driver installs the EFI_DEVICE_PATH_PROTOCOL with EFI_DEVICE_PATH_PROTOCOL_GUID,
     the SPDM_IO_PROTOCOL with SPDM_PROTOCOL_IO_GUID,
     and the device access protocol with EDKII_DEVICE_IDENTIFIER_TYPE_xxx_GUID.
     Once it is done, a DeviceHandle is returned.
  5) Device driver creates EDKII_DEVICE_IDENTIFIER with EDKII_DEVICE_IDENTIFIER_TYPE_xxx_GUID
     and the DeviceHandle.
  6) Device driver calls DeviceAuthenticate().
  7) If DeviceAuthenticate() returns EFI_SECURITY_VIOLATION, the device driver uninstalls
     all protocols on this handle.
  8) If DeviceAuthenticate() returns EFI_SUCCESS, the device driver installs the device access
     protocol with a real protocol GUID. e.g.
     EFI_PCI_IO_PROTOCOL with EFI_PCI_IO_PROTOCOL_GUID.
     EFI_USB_IO_PROTOCOL with EFI_USB_IO_PROTOCOL_GUID.

  @param[in]  This              The protocol instance pointer.
  @param[in]  DeviceId          The Identifier for the device.

  @retval EFI_SUCCESS              The device specified by the DeviceId passed the measurement
                                   and/or authentication based upon the platform policy.
                                   If TCG measurement is required, the measurement is extended to TPM PCR.
  @retval EFI_SECURITY_VIOLATION   The device fails to return the measurement data.
  @retval EFI_SECURITY_VIOLATION   The device fails to response the authentication request.
  @retval EFI_SECURITY_VIOLATION   The system fails to verify the device based upon the authentication response.
  @retval EFI_SECURITY_VIOLATION   The system fails to extend the measurement to TPM PCR.
**/
EFI_STATUS
EFIAPI
DeviceAuthentication (
  IN EDKII_DEVICE_SECURITY_PPI  *This,
  IN EDKII_DEVICE_IDENTIFIER    *DeviceId
  )
{
  DEBUG ((DEBUG_INFO, "\n\n\n\n%a: DONE...\n\n\n\n\n", __func__));
  ASSERT (FALSE);

  return EFI_SUCCESS;
}

EDKII_DEVICE_SECURITY_PPI mDeviceSecurityPpi = {
  EDKII_DEVICE_SECURITY_PPI_REVISION,
  DeviceAuthentication
};

EFI_PEI_PPI_DESCRIPTOR  mDeviceSecurityPpiList = {
  EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST,
  &gEdkiiDeviceSecurityPpiGuid,
  &mDeviceSecurityPpi
};

/**
  Entrypoint of the device security driver.

  @param[in]  ImageHandle  ImageHandle of the loaded driver
  @param[in]  SystemTable  Pointer to the System Table

  @retval  EFI_SUCCESS           The Protocol is installed.
  @retval  EFI_OUT_OF_RESOURCES  Not enough resources available to initialize
driver.
  @retval  EFI_DEVICE_ERROR      A device error occurred attempting to
initialize the driver.

**/
EFI_STATUS
EFIAPI
MainEntryPoint(
  IN EFI_PEI_FILE_HANDLE FileHandle,
  IN CONST EFI_PEI_SERVICES **PeiServices
  )
{
  EFI_STATUS Status;

  // Status = PeiServicesLocatePpi (
  //           &gEdkiiDeviceSecurityPolicyPpiGuid,
  //           0,
  //           NULL,
  //           (VOID **)&mDeviceSecurityPolicyPpi
  //           );
  // ASSERT(FALSE);
  // if (EFI_ERROR(Status)) {
  //   return Status;
  // }

  Status = PeiServicesInstallPpi (&mDeviceSecurityPolicyPpiList);
  ASSERT_EFI_ERROR (Status);

  //
  // install Device Security Services
  //
  Status = PeiServicesInstallPpi(&mDeviceSecurityPpiList);
  ASSERT_EFI_ERROR(Status);

  // InitializeSpdmCommunication();

  return Status;
}
