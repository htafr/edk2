#include "SpdmSecurityLibInternal.h"

EFI_STATUS
EFIAPI
DoDeviceSecureSession(
  IN  SPDM_DEVICE_CONTEXT     *SpdmDeviceContext,
  IN  EDKII_SPDM_DEVICE_INFO  *SpdmDeviceInfo
)
{
  EFI_STATUS    Status;
  SPDM_RETURN   SpdmReturn;
  VOID          *SpdmContext;
  UINT32        SessionId;
  UINT8         HeartbeatPeriod;
  UINT8         MeasurementHash[LIBSPDM_MAX_HASH_SIZE];
  // UINTN         ResponseSize;
  // BOOLEAN       Result;
  // UINT32        Response;

  Status = EFI_SUCCESS;
  SpdmContext = SpdmDeviceContext->SpdmContext;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof (MeasurementHash));
  SpdmReturn = SpdmStartSession (
            SpdmContext, FALSE, NULL, 0,
            SpdmDeviceInfo->MeasurementSummaryHashType,
            SpdmDeviceInfo->SlotId,
            SpdmDeviceInfo->SessionPolicy,
            &SessionId, &HeartbeatPeriod, MeasurementHash
            );
  if (LIBSPDM_STATUS_IS_SUCCESS (SpdmReturn)) {
    DEBUG ((DEBUG_ERROR, "SpdmStartSession error - 0x%lX\n", SpdmReturn));
    Status =  EFI_UNSUPPORTED;
  }

  return Status;
}
