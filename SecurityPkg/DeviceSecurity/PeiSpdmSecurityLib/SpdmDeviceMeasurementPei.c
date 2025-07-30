#include "PeiSpdmSecurityLibInternal.h"

/**
  This function gets SPDM measurement and extend to TPM.

  @param[in]  SpdmDeviceContext            The SPDM context for the device.
  @param[in]  SlotId                       The number of slot id of the certificate.
  @param[out] SecurityState                A poniter to security state of the requester.

  @retval EFI_SUCCESS            Operation completed successfully.
  @retval EFI_OUT_OF_RESOURCES   Out of memory.
  @retval EFI_DEVICE_ERROR       The operation was unsuccessful.

**/
EFI_STATUS
EFIAPI
DoDeviceMeasurement (
  IN  SPDM_DEVICE_CONTEXT          *SpdmDeviceContext,
  IN  UINT8                        SlotId,
  OUT EDKII_DEVICE_SECURITY_STATE  *SecurityState
  )
{
  SPDM_RETURN                  SpdmReturn;
  VOID                         *SpdmContext;
  UINT32                       CapabilityFlags;
  UINTN                        DataSize;
  SPDM_DATA_PARAMETER          Parameter;
  UINT8                        NumberOfBlocks;
  UINT32                       MeasurementRecordLength;
  UINT8                        MeasurementRecord[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
  UINT8                        Index;
  UINT8                        RequesterNonce[SPDM_NONCE_SIZE];
  UINT8                        ResponderNonce[SPDM_NONCE_SIZE];
  UINT8                        RequestAttribute;
  UINT32                       MeasurementsBlockSize;
  SPDM_MEASUREMENT_BLOCK_DMTF  *MeasurementBlock;
  UINT8                        NumberOfBlock;
  UINT8                        ReceivedNumberOfBlock;
  UINT8                        ContentChanged;
  UINT8                        ContentChangedCount;

  SpdmContext = SpdmDeviceContext->SpdmContext;

  ZeroMem (&Parameter, sizeof (Parameter));
  Parameter.location = SpdmDataLocationConnection;
  DataSize           = sizeof (CapabilityFlags);
  SpdmGetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &CapabilityFlags, &DataSize);

  if ((CapabilityFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) == 0) {
    SecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_ERROR_DEVICE_NO_CAPABILITIES;
  }

  RequestAttribute  = 0;
  RequestAttribute |= SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof (MeasurementRecord);
  ZeroMem (RequesterNonce, sizeof (RequesterNonce));
  ZeroMem (ResponderNonce, sizeof (ResponderNonce));

  //
  // get all measurement once, with signature.
  //
  SpdmReturn = SpdmGetMeasurementEx (
                 SpdmContext,
                 NULL,
                 RequestAttribute,
                 SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
                 SlotId,
                 NULL,
                 &NumberOfBlocks,
                 &MeasurementRecordLength,
                 MeasurementRecord,
                 NULL,
                 RequesterNonce,
                 ResponderNonce,
                 NULL,
                 0
                 );
  if (LIBSPDM_STATUS_IS_SUCCESS (SpdmReturn)) {
    DEBUG ((DEBUG_INFO, "NumberOfBlocks %d\n", NumberOfBlocks));

    MeasurementBlock = (VOID *)MeasurementRecord;
    for (Index = 0; Index < NumberOfBlocks; Index++) {
      MeasurementsBlockSize =
        sizeof (SPDM_MEASUREMENT_BLOCK_DMTF) +
        MeasurementBlock
          ->MeasurementBlockDmtfHeader
          .DMTFSpecMeasurementValueSize;

      SecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_SUCCESS;

      MeasurementBlock = (VOID *)((size_t)MeasurementBlock + MeasurementsBlockSize);
    }
  } else if (SpdmReturn == LIBSPDM_STATUS_VERIF_FAIL) {
    SecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_ERROR_MEASUREMENT_AUTH_FAILURE;
    return EFI_DEVICE_ERROR;
  } else {
    ContentChangedCount = 0;
ContentChangedFlag:
    RequestAttribute      = 0;
    ContentChanged        = SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED;
    ReceivedNumberOfBlock = 0;

    //
    // 1. Query the total number of measurements available.
    //
    SpdmReturn = SpdmGetMeasurement (
                   SpdmContext,
                   NULL,
                   RequestAttribute,
                   SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
                   SlotId,
                   NULL,
                   &NumberOfBlocks,
                   NULL,
                   NULL
                   );
    if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
      SecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_ERROR_DEVICE_ERROR;
      return EFI_DEVICE_ERROR;
    }

    DEBUG ((DEBUG_INFO, "NumberOfBlocks - 0x%x\n", NumberOfBlocks));

    ReceivedNumberOfBlock = 0;
    for (Index = 1; Index <= 0xFE; Index++) {
      if (ReceivedNumberOfBlock == NumberOfBlocks) {
        break;
      }

      DEBUG ((DEBUG_INFO, "Index - 0x%x\n", Index));
      //
      // 2. query measurement one by one
      //    get signature in last message only.
      //
      if (ReceivedNumberOfBlock == NumberOfBlocks - 1) {
        RequestAttribute |= SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
      }

      MeasurementRecordLength = sizeof (MeasurementRecord);
      ZeroMem (RequesterNonce, sizeof (RequesterNonce));
      ZeroMem (ResponderNonce, sizeof (ResponderNonce));
      SpdmReturn = SpdmGetMeasurementEx (
                     SpdmContext,
                     NULL,
                     RequestAttribute,
                     Index,
                     SlotId,
                     &ContentChanged,
                     &NumberOfBlock,
                     &MeasurementRecordLength,
                     MeasurementRecord,
                     NULL,
                     RequesterNonce,
                     ResponderNonce,
                     NULL,
                     0
                     );
      if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
        if (SpdmReturn == LIBSPDM_STATUS_VERIF_FAIL) {
          SecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_ERROR_DEVICE_ERROR;
          return EFI_DEVICE_ERROR;
        } else {
          continue;
        }
      }

      if ((ReceivedNumberOfBlock == NumberOfBlocks - 1) &&
          (ContentChanged == SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_DETECTED))
      {
        if (ContentChangedCount == 0) {
          ContentChangedCount++;
          goto ContentChangedFlag;
        } else {
          SecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_ERROR_DEVICE_ERROR;
          return EFI_DEVICE_ERROR;
        }
      }

      SecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_SUCCESS;
      ReceivedNumberOfBlock += 1;
    }

    if (ReceivedNumberOfBlock != NumberOfBlocks) {
      SecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_ERROR_MEASUREMENT_AUTH_FAILURE;
      return EFI_DEVICE_ERROR;
    }
  }

  return EFI_SUCCESS;
}
