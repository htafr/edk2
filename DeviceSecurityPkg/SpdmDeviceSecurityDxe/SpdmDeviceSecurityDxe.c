#include "SpdmDeviceSecurityDxe.h"

BOOLEAN mSendReceiveBufferAcquired = FALSE;
VOID    *SpdmMsgBuffer;

EDKII_DEVICE_SECURITY_POLICY  mDeviceSecurityPolicyNone = {
  EDKII_DEVICE_SECURITY_POLICY_REVISION,
  0,
  0,
};

EDKII_DEVICE_SECURITY_POLICY  mDeviceSecurityPolicyFull = {
  EDKII_DEVICE_SECURITY_POLICY_REVISION,
  EDKII_DEVICE_MEASUREMENT_REQUIRED,
  EDKII_DEVICE_AUTHENTICATION_REQUIRED
};

EDKII_DEVICE_SECURITY_POLICY  mDeviceSecurityPolicyAuthOnly = {
  EDKII_DEVICE_SECURITY_POLICY_REVISION,
  0,
  EDKII_DEVICE_AUTHENTICATION_REQUIRED
};

EDKII_DEVICE_SECURITY_POLICY  mDeviceSecurityPolicyMeasOnly = {
  EDKII_DEVICE_SECURITY_POLICY_REVISION,
  EDKII_DEVICE_MEASUREMENT_REQUIRED,
  0
};

SPDM_RETURN
SpdmDeviceAcquireBuffer (
  VOID  *Context,
  VOID  **MsgBufPtr
  )
{
  ASSERT (!mSendReceiveBufferAcquired);
  SpdmMsgBuffer = AllocateZeroPool (LIBSPDM_MAX_SPDM_MSG_SIZE);
  *MsgBufPtr = SpdmMsgBuffer;
  mSendReceiveBufferAcquired = TRUE;

  return LIBSPDM_STATUS_SUCCESS;
}

VOID
SpdmDeviceReleaseBuffer (
  VOID        *Context,
  CONST VOID  *MsgBufPtr
  )
{
  ASSERT (mSendReceiveBufferAcquired);
  FreePool (SpdmMsgBuffer);
  mSendReceiveBufferAcquired = FALSE;

  return;
}

SPDM_RETURN
SpdmIoProtocolDeviceSendMessage (
  IN    VOID        *SpdmContext,
  IN    UINTN       MessageSize,
  IN    CONST VOID  *Message,
  IN    UINT64      Timeout
  )
{
  SPDM_IO_PROTOCOL *SpdmIoProtocol;

  SpdmIoProtocol = SpdmGetIoProtocolViaSpdmContext (SpdmContext);
  if (SpdmIoProtocol == NULL) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  return SpdmIoProtocol->SendMessage (SpdmIoProtocol, MessageSize, Message, Timeout);
}

SPDM_RETURN
SpdmIoProtocolDeviceReceiveMessage (
  IN      VOID    *SpdmContext,
  IN OUT  UINTN   *MessageSize,
  IN OUT  VOID    **Message,
  IN      UINT64  Timeout
  )
{
  SPDM_IO_PROTOCOL *SpdmIoProtocol;

  SpdmIoProtocol = SpdmGetIoProtocolViaSpdmContext (SpdmContext);
  if (SpdmIoProtocol == NULL) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  return SpdmIoProtocol->ReceiveMessage (SpdmIoProtocol, MessageSize, Message, Timeout);
}

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
  IN  EDKII_DEVICE_SECURITY_POLICY_PROTOCOL  *This,
  IN  EDKII_DEVICE_IDENTIFIER                *DeviceId,
  OUT EDKII_DEVICE_SECURITY_POLICY           *DeviceSecurityPolicy
  )
{
  EFI_STATUS                Status;
  EFI_PCI_IO_PROTOCOL       *PciIo;
  EFI_USB_IO_PROTOCOL       *UsbIo;
  EFI_USB_DEVICE_DESCRIPTOR *UsbDevDesc;
  SPDM_DEVICE_BUS_TYPE      BusType;
  UINT16                    PciVendorId;
  UINT16                    PciDeviceId;

  CopyMem (DeviceSecurityPolicy, &mDeviceSecurityPolicyNone, sizeof (EDKII_DEVICE_SECURITY_POLICY));

  if (CompareGuid (&DeviceId->DeviceType, &gEdkiiDeviceIdentifierTypePciGuid)) {
    BusType = SPDM_DEVICE_PCI_TYPE;
  } else if (CompareGuid (&DeviceId->DeviceType, &gEdkiiDeviceIdentifierTypeUsbGuid)) {
    BusType = SPDM_DEVICE_USB_TYPE;
  } else {
    return EFI_SUCCESS;
  }

  if (BusType == SPDM_DEVICE_PCI_TYPE) {
    Status = gBS->HandleProtocol (
                    DeviceId->DeviceHandle,
                    &gEdkiiDeviceIdentifierTypePciGuid,
                    (VOID **)&PciIo
                    );
    if (EFI_ERROR (Status)) {
      return EFI_SUCCESS;
    }

    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16, PCI_VENDOR_ID_OFFSET, 1, &PciVendorId);
    ASSERT_EFI_ERROR (Status);
    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16, PCI_DEVICE_ID_OFFSET, 1, &PciDeviceId);
    ASSERT_EFI_ERROR (Status);
  } else if (BusType == SPDM_DEVICE_USB_TYPE) {
    Status = gBS->HandleProtocol (
                    DeviceId->DeviceHandle,
                    &gEdkiiDeviceIdentifierTypeUsbGuid,
                    (VOID **)&UsbIo
                    );

    if (EFI_ERROR (Status)) {
      return EFI_SUCCESS;
    }

    UsbDevDesc = AllocateZeroPool (sizeof (EFI_USB_DEVICE_DESCRIPTOR));
    Status = UsbIo->UsbGetDeviceDescriptor (UsbIo, UsbDevDesc);
    ASSERT_EFI_ERROR (Status);
  }


  /**
   * TODO: The device security policy can change among structs
   * defined in this file
   */
  CopyMem (DeviceSecurityPolicy, &mDeviceSecurityPolicyFull, sizeof (EDKII_DEVICE_SECURITY_POLICY));

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
  IN  EDKII_DEVICE_SECURITY_POLICY_PROTOCOL  *This,
  IN  EDKII_DEVICE_IDENTIFIER                *DeviceId,
  IN  EDKII_DEVICE_SECURITY_STATE            *DeviceSecurityState
  )
{
  EFI_STATUS                Status;
  EFI_PCI_IO_PROTOCOL       *PciIo;
  EFI_USB_IO_PROTOCOL       *UsbIo;
  EFI_USB_DEVICE_DESCRIPTOR *UsbDevDesc;
  SPDM_DEVICE_BUS_TYPE      BusType;
  UINT16                    PciVendorId;
  UINT16                    PciDeviceId;
  UINTN                     Segment;
  UINTN                     Bus;
  UINTN                     Device;
  UINTN                     Function;

  if (CompareGuid (&DeviceId->DeviceType, &gEdkiiDeviceIdentifierTypePciGuid)) {
    BusType = SPDM_DEVICE_PCI_TYPE;
  } else if (CompareGuid (&DeviceId->DeviceType, &gEdkiiDeviceIdentifierTypeUsbGuid)) {
    BusType = SPDM_DEVICE_USB_TYPE;
  } else {
    return EFI_SUCCESS;
  }

  if (BusType == SPDM_DEVICE_PCI_TYPE) {
    Status = gBS->HandleProtocol (
                    DeviceId->DeviceHandle,
                    &gEdkiiDeviceIdentifierTypePciGuid,
                    (VOID **)&PciIo
                    );
    if (EFI_ERROR (Status)) {
      return EFI_SUCCESS;
    }

    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16, PCI_VENDOR_ID_OFFSET, 1, &PciVendorId);
    ASSERT_EFI_ERROR (Status);
    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16, PCI_DEVICE_ID_OFFSET, 1, &PciDeviceId);
    ASSERT_EFI_ERROR (Status);

    Status = PciIo->GetLocation (
                      PciIo,
                      &Segment,
                      &Bus,
                      &Device,
                      &Function
                      );
    if (!EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_INFO,
        "%a: PCI Loc - %04x:%02x:%02x%02x\n",
        __func__,
        Segment,
        Bus,
        Device,
        Function
        ));
    }
  } else if (BusType == SPDM_DEVICE_USB_TYPE) {
    Status = gBS->HandleProtocol (
                    DeviceId->DeviceHandle,
                    &gEdkiiDeviceIdentifierTypeUsbGuid,
                    (VOID **)&UsbIo
                    );
    if (EFI_ERROR (Status)) {
      return EFI_SUCCESS;
    }

    UsbDevDesc = AllocateZeroPool (sizeof (EFI_USB_DEVICE_DESCRIPTOR));
    Status = UsbIo->UsbGetDeviceDescriptor (UsbIo, UsbDevDesc);
    if (!EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_INFO,
        "%a: USB Device - %04x:%04x:%02x:%02x\n",
        __func__,
        UsbDevDesc->IdVendor,
        UsbDevDesc->IdProduct,
        UsbDevDesc->DescriptorType,
        UsbDevDesc->NumConfigurations
        ));
    }
  }

  DEBUG ((
    DEBUG_INFO,
    "State - Measurement - 0x%08x, Authentication - 0x%08x\n",
    DeviceSecurityState->MeasurementState,
    DeviceSecurityState->AuthenticationState
    ));

  return EFI_SUCCESS;
}


/* Initialize Device Security Policy Protocol */
EDKII_DEVICE_SECURITY_POLICY_PROTOCOL mDeviceSecurityPolicyProtocol = {
  EDKII_DEVICE_SECURITY_PROTOCOL_REVISION,
  GetDevicePolicy,
  NotifyDeviceState
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
  IN EDKII_DEVICE_SECURITY_PROTOCOL  *This,
  IN EDKII_DEVICE_IDENTIFIER         *DeviceId
  )
{
  EDKII_DEVICE_SECURITY_POLICY          DeviceSecurityPolicy;
  EDKII_DEVICE_SECURITY_STATE           DeviceSecurityState;
  EFI_STATUS                            Status;
  UINTN                                 BufferSize;
  EFI_HANDLE                            Handle;
  EDKII_PCI_DOE_PROTOCOL                *PciDoeProtocol;
  EDKII_USB_SPDM_PROTOCOL               *UsbSpdmProtocol;
  EDKII_SPDM_DEVICE_INFO                SpdmDeviceInfo;
  SPDM_DEVICE_BUS_TYPE                  BusType;

  if (CompareGuid (&DeviceId->DeviceType, &gEdkiiDeviceIdentifierTypePciGuid)) {
    BusType = SPDM_DEVICE_PCI_TYPE;
  } else if (CompareGuid (&DeviceId->DeviceType, &gEdkiiDeviceIdentifierTypeUsbGuid)) {
    BusType = SPDM_DEVICE_USB_TYPE;
  } else {
    return EFI_SUCCESS;
  }

  ZeroMem (&SpdmDeviceInfo, sizeof (SpdmDeviceInfo));
  SpdmDeviceInfo.DeviceId                   = DeviceId;
  SpdmDeviceInfo.SendMessage                = SpdmIoProtocolDeviceSendMessage;
  SpdmDeviceInfo.ReceiveMessage             = SpdmIoProtocolDeviceReceiveMessage;

  SpdmDeviceInfo.MaxSpdmMsgSize             = LIBSPDM_MAX_SPDM_MSG_SIZE;
  SpdmDeviceInfo.TransportHeaderSize        = LIBSPDM_TRANSPORT_HEADER_SIZE;
  SpdmDeviceInfo.TransportTailSize          = LIBSPDM_TRANSPORT_TAIL_SIZE;

  if (BusType == SPDM_DEVICE_PCI_TYPE) {
    SpdmDeviceInfo.TransportEncodeMessage     = SpdmTransportPciDoeEncodeMessage;
    SpdmDeviceInfo.TransportDecodeMessage     = SpdmTransportPciDoeDecodeMessage;
  } else if (BusType == SPDM_DEVICE_USB_TYPE) {
    SpdmDeviceInfo.TransportEncodeMessage     = SpdmTransportMctpEncodeMessage;
    SpdmDeviceInfo.TransportDecodeMessage     = SpdmTransportMctpDecodeMessage;
  }

  SpdmDeviceInfo.SenderBufferSize           = LIBSPDM_MAX_SPDM_MSG_SIZE;
  SpdmDeviceInfo.ReceiverBufferSize         = LIBSPDM_MAX_SPDM_MSG_SIZE;
  SpdmDeviceInfo.AcquireSenderBuffer        = SpdmDeviceAcquireBuffer;
  SpdmDeviceInfo.ReleaseSenderBuffer        = SpdmDeviceReleaseBuffer;
  SpdmDeviceInfo.AcquireReceiverBuffer      = SpdmDeviceAcquireBuffer;
  SpdmDeviceInfo.ReleaseReceiverBuffer      = SpdmDeviceReleaseBuffer;

  SpdmDeviceInfo.Version                    = SPDM_MESSAGE_VERSION_13;
  SpdmDeviceInfo.SecuredMessageVersion      = SECURED_SPDM_VERSION_11;
  SpdmDeviceInfo.RequesterCapabilityFlags   = (0 |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | /* conflict with SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP */
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP |
                                              /* SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP |    conflict with SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP   */
                                              SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG |
                                              0);
  SpdmDeviceInfo.CapabilityFlags            = 0;
  SpdmDeviceInfo.BasicMutAuth               = 0;
  SpdmDeviceInfo.MutAuth                    = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
  SpdmDeviceInfo.MeasurementSummaryHashType = SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH;
  SpdmDeviceInfo.MeasurementOperation       = SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS;
  SpdmDeviceInfo.SlotId                     = 0;
  SpdmDeviceInfo.SlotCount                  = 3;
  SpdmDeviceInfo.MeasurementSpec            = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
  SpdmDeviceInfo.MeasurementHashAlgo        = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
                                              SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
                                              SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmDeviceInfo.ReqBaseAsymAlgo            = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
  SpdmDeviceInfo.DheAlgo                    = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                              SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
  SpdmDeviceInfo.AeadAlgo                   = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                              SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM;
  SpdmDeviceInfo.KeyScheduleAlgo            = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
  SpdmDeviceInfo.OtherParamsSupport         = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1 |
                                              SPDM_ALGORITHMS_MULTI_KEY_CONN;
  SpdmDeviceInfo.MelSpec                    = SPDM_MEL_SPECIFICATION_DMTF;

  SpdmDeviceInfo.SpdmIoProtocolGuid = &gSpdmIoProtocolGuid;

  DeviceSecurityState.Revision            = EDKII_DEVICE_SECURITY_POLICY_REVISION;
  DeviceSecurityState.MeasurementState    = 0x0;
  DeviceSecurityState.AuthenticationState = 0x0;

  if (BusType == SPDM_DEVICE_PCI_TYPE) {
      // Just install SpdmIoProtocol if exists PciDoeProtocol
      BufferSize = sizeof (Handle);
      Status     = gBS->LocateHandle (
                          ByProtocol,
                          &gEdkiiPciDoeProtocol,
                          NULL,
                          &BufferSize,
                          &Handle
                          );
      if (Status != EFI_SUCCESS) {
        return EFI_SUCCESS;
      }

      Status = gBS->HandleProtocol (
                      Handle,
                      &gEdkiiPciDoeProtocol,
                      (VOID **)&PciDoeProtocol
                      );
      if (PciDoeProtocol == NULL) {
        return EFI_SUCCESS;
      }
  } else if (BusType == SPDM_DEVICE_USB_TYPE) {
    BufferSize = sizeof (Handle);
    Status     = gBS->LocateHandle (
                        ByProtocol,
                        &gEdkiiUsbSpdmProtocolGuid,
                        NULL,
                        &BufferSize,
                        &Handle
                        );

    Status = gBS->HandleProtocol (
                    Handle,
                    &gEdkiiUsbSpdmProtocolGuid,
                    (VOID **)&UsbSpdmProtocol
                    );
    if (UsbSpdmProtocol == NULL) {
      return EFI_SUCCESS;
    }
  }

  Status = InstallSpdmIoProtocol (&DeviceId->DeviceHandle);
  if (Status != EFI_SUCCESS) {
    return EFI_SUCCESS;
  }

  Status = mDeviceSecurityPolicyProtocol.GetDevicePolicy (&mDeviceSecurityPolicyProtocol, DeviceId, &DeviceSecurityPolicy);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: mDeviceSecurityPolicy->GetDevicePolicy - %r\n", __func__, Status));
    DeviceSecurityState.MeasurementState    = EDKII_DEVICE_SECURITY_STATE_ERROR_UEFI_GET_POLICY_PROTOCOL;
    DeviceSecurityState.AuthenticationState = EDKII_DEVICE_SECURITY_STATE_ERROR_UEFI_GET_POLICY_PROTOCOL;
  } else {
    Status = SpdmDeviceAuthenticationAndMeasurement (&SpdmDeviceInfo, &DeviceSecurityPolicy, &DeviceSecurityState);
  }

  Status = mDeviceSecurityPolicyProtocol.NotifyDeviceState (&mDeviceSecurityPolicyProtocol, DeviceId, &DeviceSecurityState);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: mDeviceSecurityPolicy->NotifyDeviceState - %r\n", __func__, Status));
  }

  if ((DeviceSecurityState.MeasurementState == 0) &&
      (DeviceSecurityState.AuthenticationState == 0)) {
    Status = EFI_SUCCESS;
  } else {
    Status = EFI_SECURITY_VIOLATION;
  }

  UninstallSpdmIoProtocol (&Handle);
  return Status;
}

EDKII_DEVICE_SECURITY_PROTOCOL mDeviceSecurity = {
  EDKII_DEVICE_SECURITY_PROTOCOL_REVISION,
  DeviceAuthentication
};

/**

  Entrypoint of SpdmDeviceSecurityDxe

  @param[in]  ImageHandle   ImageHandle of the loaded driver
  @param[in]  SystemTable   Pointer to the SystemTable

  @retval     EFI_SUCCESS          The Protocol is installed
  @retval     EFI_OUT_OF_RESOUCES  Not enough resources available to initialize driver
  @retval     EFI_DEVICE_ERROR     A device error occurred attempting to initialize the driver

**/
EFI_STATUS
EFIAPI
SpdmDeviceSecurityEntryPoint (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_HANDLE Handle;
  EFI_STATUS Status;
  UINT8      AuthBootMode = 1;

  Status = gRT->SetVariable (
                  EFI_DEVICE_AUTH_BOOT_MODE_NAME,
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  sizeof (UINT8),
                  &AuthBootMode
                  );

  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEdkiiDeviceSecurityPolicyProtocolGuid,
                  (VOID **)&mDeviceSecurityPolicyProtocol,
                  &gEdkiiDeviceSecurityProtocolGuid,
                  (VOID **)&mDeviceSecurity,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  return Status;
}
