#include <Library/PeiServicesLib.h>
#include <Library/PeiServicesTablePointerLib.h>
#include "PeiSpdmSecurityLibInternal.h"
#include "Certificates.h"

LIST_ENTRY  mSpdmDeviceContextList = INITIALIZE_LIST_HEAD_VARIABLE (mSpdmDeviceContextList);

/**
  record Spdm Io protocol into the context list.

  @param[in]  SpdmDeviceContext      The SPDM context of the device.

**/
VOID
RecordSpdmDeviceContextInList (
  IN SPDM_DEVICE_CONTEXT  *SpdmDeviceContext
  )
{
  SPDM_DEVICE_CONTEXT_INSTANCE  *NewSpdmDeviceContext;
  LIST_ENTRY                    *SpdmDeviceContextList;

  SpdmDeviceContextList = &mSpdmDeviceContextList;

  NewSpdmDeviceContext = AllocateZeroPool (sizeof (*NewSpdmDeviceContext));
  if (NewSpdmDeviceContext == NULL) {
    ASSERT (NewSpdmDeviceContext != NULL);
    return;
  }

  NewSpdmDeviceContext->Signature         = SPDM_DEVICE_CONTEXT_INSTANCE_SIGNATURE;
  NewSpdmDeviceContext->SpdmDeviceContext = SpdmDeviceContext;

  InsertTailList (SpdmDeviceContextList, &NewSpdmDeviceContext->Link);
}

/**
  This function creates the spdm device context and init connection to the
  responder with the device info.

  @param[in]  SpdmDeviceInfo        A pointer to device info.
  @param[out] SecurityState         A pointer to the security state of the requester.

  @return the spdm device conext after the init connection succeeds.

**/
SPDM_DEVICE_CONTEXT *
EFIAPI
CreateSpdmDeviceContext (
  IN  EDKII_SPDM_DEVICE_INFO       *SpdmDeviceInfo,
  OUT EDKII_DEVICE_SECURITY_STATE  *SecurityState
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmDeviceContext;
  VOID                 *SpdmContext;
  UINTN                SpdmContextSize;
  VOID                 *ScratchBuffer;
  UINTN                ScratchBufferSize;
  // EFI_STATUS           Status;
  SPDM_VERSION_NUMBER  SpdmVersion;
  SPDM_RETURN          SpdmReturn;
  // EFI_SIGNATURE_LIST   *DbList;
  // EFI_SIGNATURE_DATA   *Cert;
  // UINTN                CertCount;
  // UINTN                Index;
  // UINTN                SiglistHeaderSize;
  // UINTN                DbSize;
  // VOID                 *Data;
  UINTN                DataSize;
  SPDM_DATA_PARAMETER  Parameter;
  UINT8                Data8;
  UINT16               Data16;
  UINT32               Data32;
  // UINT8                AuthState;

  SpdmDeviceContext = AllocateZeroPool (sizeof (*SpdmDeviceContext));
  if (SpdmDeviceContext == NULL) {
    ASSERT (SpdmDeviceContext != NULL);
    return NULL;
  }

  SpdmDeviceContext->Signature = SPDM_DEVICE_CONTEXT_SIGNATURE;
  CopyMem (&SpdmDeviceContext->DeviceId, SpdmDeviceInfo->DeviceId, sizeof (EDKII_DEVICE_IDENTIFIER));
  SpdmDeviceContext->IsEmbeddedDevice = SpdmDeviceInfo->IsEmbeddedDevice;

  SpdmContextSize = SpdmGetContextSize ();
  SpdmContext     = AllocateZeroPool (SpdmContextSize);
  if (SpdmContext == NULL) {
    ASSERT (SpdmContext != NULL);
    goto Error;
  }

  SpdmReturn = SpdmInitContext (SpdmContext);
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    goto Error;
  }

  SpdmRegisterDeviceIoFunc (
    SpdmContext,
    SpdmDeviceInfo->SendMessage,
    SpdmDeviceInfo->ReceiveMessage
    );
  SpdmRegisterTransportLayerFunc (
    SpdmContext,
    SpdmDeviceInfo->MaxSpdmMsgSize,
    SpdmDeviceInfo->TransportHeaderSize,
    SpdmDeviceInfo->TransportTailSize,
    SpdmDeviceInfo->TransportEncodeMessage,
    SpdmDeviceInfo->TransportDecodeMessage
    );

  SpdmRegisterDeviceBufferFunc (
    SpdmContext,
    SpdmDeviceInfo->SenderBufferSize,
    SpdmDeviceInfo->ReceiverBufferSize,
    SpdmDeviceInfo->AcquireSenderBuffer,
    SpdmDeviceInfo->ReleaseSenderBuffer,
    SpdmDeviceInfo->AcquireReceiverBuffer,
    SpdmDeviceInfo->ReleaseReceiverBuffer
    );

  ScratchBufferSize = SpdmGetSizeofRequiredScratchBuffer (SpdmContext);
  ScratchBuffer     = AllocateZeroPool (ScratchBufferSize);
  if (ScratchBuffer == NULL) {
    ASSERT (ScratchBuffer != NULL);
    goto Error;
  }

  SpdmSetScratchBuffer (SpdmContext, ScratchBuffer, ScratchBufferSize);

  SpdmDeviceContext->SpdmContextSize   = SpdmContextSize;
  SpdmDeviceContext->SpdmContext       = SpdmContext;
  SpdmDeviceContext->ScratchBufferSize = ScratchBufferSize;
  SpdmDeviceContext->ScratchBuffer     = ScratchBuffer;

  // Status = PeiServicesLocatePpi (
  //             &gSpdmIoPpiGuid,
  //             0,
  //             NULL,
  //             (VOID **)&SpdmDeviceContext->SpdmIoPpi
  //             );
  // if (EFI_ERROR(Status)) {
  //   DEBUG ((DEBUG_ERROR, "Locate - SpdmIoPpi - %r\n", Status));
  //   goto Error;
  // }
  //
  // Status = PeiServicesLocatePpi (
  //            &gSpdmPpiGuid,
  //            0,
  //            NULL,
  //            (VOID**)&SpdmDeviceContext->SpdmPpi
  //            );
  // if (EFI_ERROR(Status)) {
  //   DEBUG ((DEBUG_ERROR, "Locate - SpdmPpi - %r\n", Status));
  //   goto Error;
  // }

  RecordSpdmDeviceContextInList (SpdmDeviceContext);

  if (SpdmDeviceInfo->Version != 0) {
    ZeroMem (&Parameter, sizeof (Parameter));
    Parameter.location = SpdmDataLocationLocal;
    SpdmVersion = SpdmDeviceInfo->Version << SPDM_VERSION_NUMBER_SHIFT_BIT;
    SpdmReturn = SpdmSetData (SpdmContext, SpdmDataSpdmVersion, &Parameter, &SpdmVersion, sizeof (SpdmVersion));
    if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
      ASSERT (FALSE);
      goto Error;
    }
  }

  if (SpdmDeviceInfo->SecuredMessageVersion != 0) {
    ZeroMem (&Parameter, sizeof (Parameter));
    Parameter.location = SpdmDataLocationLocal;
    SpdmVersion = SpdmDeviceInfo->SecuredMessageVersion << SPDM_VERSION_NUMBER_SHIFT_BIT;
    SpdmReturn = SpdmSetData (SpdmContext, SpdmDataSecuredMessageVersion, &Parameter, &SpdmVersion, sizeof (SpdmVersion));
    if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
      ASSERT (FALSE);
      goto Error;
    }
  }

  Data8 = 0;
  ZeroMem (&Parameter, sizeof (Parameter));
  Parameter.location = SpdmDataLocationLocal;
  SpdmReturn         = SpdmSetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, sizeof (Data8));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->RequesterCapabilityFlags != 0) {
    Data32 = SpdmDeviceInfo->RequesterCapabilityFlags;
  } else {
    Data32 = 0;
  }
  if (SpdmDeviceInfo->SlotId == 0xFF) {
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP;
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP;
  }
  if (SpdmDeviceInfo->CapabilityFlags != 0) {
    Data32 = SpdmDeviceInfo->CapabilityFlags;
    SpdmDeviceInfo->RequesterCapabilityFlags = Data32;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof (Data32));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->MeasurementSpec != 0) {
    Data8 = SpdmDeviceInfo->MeasurementSpec;
  } else {
    Data8 = 0;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataMeasurementSpec, &Parameter, &Data8, sizeof (Data8));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->BaseAsymAlgo != 0) {
    Data32 = SpdmDeviceInfo->BaseAsymAlgo;
  } else {
    Data32 = 0;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, sizeof (Data32));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->BaseHashAlgo != 0) {
    Data32 = SpdmDeviceInfo->BaseHashAlgo;
  } else {
    Data32 = 0;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, sizeof (Data32));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->DheAlgo != 0) {
    Data16 = SpdmDeviceInfo->DheAlgo;
  } else {
    Data16 = 0;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataDHENameGroup, &Parameter, &Data16, sizeof (Data16));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->AeadAlgo != 0) {
    Data16 = SpdmDeviceInfo->AeadAlgo;
  } else {
    Data16 = 0;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &Data16, sizeof (Data16));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->ReqBaseAsymAlgo != 0) {
    Data16 = SpdmDeviceInfo->ReqBaseAsymAlgo;
  } else {
    Data16 = 0;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &Data16, sizeof (Data16));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->KeyScheduleAlgo != 0) {
    Data16 = SpdmDeviceInfo->KeyScheduleAlgo;
  } else {
    Data16 = 0;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataKeySchedule, &Parameter, &Data16, sizeof (Data16));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->OtherParamsSupport != 0) {
    Data8 = SpdmDeviceInfo->OtherParamsSupport;
  } else {
    Data8 = 0;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataOtherParamsSupport, &Parameter, &Data8, sizeof (Data8));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  if (SpdmDeviceInfo->MelSpec != 0) {
    Data8 = SpdmDeviceInfo->MelSpec;
  } else {
    Data8 = 0;
  }
  SpdmReturn = SpdmSetData (SpdmContext, SpdmDataMelSpec, &Parameter, &Data8, sizeof (Data8));
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    ASSERT (FALSE);
    goto Error;
  }

  ZeroMem (&Parameter, sizeof (Parameter));
  Parameter.location = SpdmDataLocationLocal;
  SpdmReturn         = SpdmSetData (SpdmContext, SpdmDataPeerPublicRootCert, &Parameter, &PeerPublicRootCert, PeerPublicRootCertSize);
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    DEBUG ((DEBUG_ERROR, "SpdmSetData - %p\n", SpdmReturn));
    goto Error;
  }

  SpdmReturn = SpdmInitConnection (SpdmContext, FALSE);
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    DEBUG ((DEBUG_ERROR, "SpdmInitConnection - %p\n", SpdmReturn));

    SecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_ERROR_DEVICE_NO_CAPABILITIES;

    goto Error;
  }

  ZeroMem (&Parameter, sizeof (Parameter));
  Parameter.location = SpdmDataLocationConnection;
  DataSize           = sizeof (Data16);
  SpdmReturn         = SpdmGetData (SpdmContext, SpdmDataSpdmVersion, &Parameter, &Data16, &DataSize);
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    DEBUG ((DEBUG_ERROR, "SpdmGetData - %p\n", SpdmReturn));
    goto Error;
  }

  SpdmDeviceContext->SpdmVersion = (Data16 >> SPDM_VERSION_NUMBER_SHIFT_BIT);

  return SpdmDeviceContext;
Error:
  DestroySpdmDeviceContext (SpdmDeviceContext);
  return NULL;
}

/**
  This function destories the spdm device context.

  @param[in]  SpdmDeviceContext      A pointer to device info.

**/
VOID
EFIAPI
DestroySpdmDeviceContext (
  IN SPDM_DEVICE_CONTEXT  *SpdmDeviceContext
  )
{
  // need zero memory in case of secret in memory.
  if (SpdmDeviceContext->SpdmContext != NULL) {
    ZeroMem (SpdmDeviceContext->SpdmContext, SpdmDeviceContext->SpdmContextSize);
    FreePool (SpdmDeviceContext->SpdmContext);
  }

  if (SpdmDeviceContext->ScratchBuffer != NULL) {
    ZeroMem (SpdmDeviceContext->ScratchBuffer, SpdmDeviceContext->ScratchBufferSize);
    FreePool (SpdmDeviceContext->ScratchBuffer);
  }

  if (SpdmDeviceContext->SignatureList != NULL) {
    ZeroMem (SpdmDeviceContext->SignatureList, SpdmDeviceContext->SignatureListSize);
    FreePool (SpdmDeviceContext->SignatureList);
  }

  FreePool (SpdmDeviceContext);
}

