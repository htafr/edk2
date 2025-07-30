/** @file
  EDKII Device Security library for SPDM device.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PeiSpdmSecurityLibInternal.h"

/**
  This function executes SPDM authentication.

  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
// EFI_STATUS
// DoAuthenticationViaSpdm (
//   IN  SPDM_DEVICE_CONTEXT         *SpdmDeviceContext,
//   OUT EDKII_DEVICE_SECURITY_STATE *DeviceSecurityState
//   )
// {
//   EFI_STATUS            Status;
//   VOID                  *SpdmContext;
//   UINT32                CapabilityFlags;
//   UINTN                 DataSize;
//   UINT8                 SlotMask;
//   UINT8                 TotalDigestBuffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
//   UINT8                 MeasurementHash[LIBSPDM_MAX_HASH_SIZE];
//   UINTN                 CertChainSize;
//   UINT8                 CertChain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
//   SPDM_DATA_PARAMETER   Parameter;
//   BOOLEAN               isValidChallengeAuthSig;
//
//   SpdmContext = SpdmDeviceContext->SpdmContext;
//
//   ZeroMem (&Parameter, sizeof(Parameter));
//   Parameter.location = SpdmDataLocationConnection;
//   DataSize = sizeof(CapabilityFlags);
//   SpdmGetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &CapabilityFlags, &DataSize);
//
//   if ((CapabilityFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) != 0) {
//     ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
//     Status = SpdmGetDigest (SpdmContext, NULL, &SlotMask, TotalDigestBuffer);
//     if (LIBSPDM_STATUS_IS_ERROR (Status)) {
//       DeviceSecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_ERROR_DEVICE_ERROR;
//       return EFI_DEVICE_ERROR;
//     }
//
//     CertChainSize = sizeof(CertChain);
//     ZeroMem (CertChain, sizeof(CertChain));
//     Status = SpdmGetCertificate (SpdmContext, NULL, 0, &CertChainSize, CertChain);
//     if (LIBSPDM_STATUS_IS_ERROR (Status)) {
//       DeviceSecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_ERROR_CERTIFIACTE_FAILURE;
//       return EFI_DEVICE_ERROR;
//     }
//   }
//
//   ZeroMem (MeasurementHash, sizeof(MeasurementHash));
//   Status = SpdmChallenge (SpdmContext, NULL, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
//   DeviceSecurityState->AuthenticationState = SpdmGetLastError (SpdmContext);
//   if (EFI_ERROR(Status)) {
//     return Status;
//   }
//   return EFI_SUCCESS;
// }

// /**
//   The device driver uses this service to verify an SPDM device.
//
//   @param[in]  SpdmContext            The SPDM context for the device.
//   @param[out] DeviceSecurityState    The Device Security state associated with the device.
// **/
// EFI_STATUS
// DoDeviceAuthentication (
//   IN  SPDM_DRIVER_DEVICE_CONTEXT  *SpdmDeviceContext,
//   OUT EDKII_DEVICE_SECURITY_STATE *DeviceSecurityState
//   )
// {
//   EFI_STATUS            Status;
//   VOID                 *SpdmContext;
//
//   SpdmContext = SpdmDeviceContext->SpdmContext;
//
//   DeviceSecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_SUCCESS;
//   if (IsSpdmDeviceInAuthenticationList (SpdmDeviceContext)) {
//     DeviceSecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_SUCCESS;
//     return EFI_SUCCESS;
//   }
//
//   Status = DoAuthenticationViaSpdm (SpdmDeviceContext, DeviceSecurityState);
//   if (Status != EFI_SUCCESS) {
//     return Status;
//   }
//
//   if (DeviceSecurityState->AuthenticationState == EDKII_DEVICE_SECURITY_STATE_SUCCESS) {
//     RecordSpdmDeviceInAuthenticationList (SpdmDeviceContext);
//   }
//
//   return Status;
// }

/**
  Record an SPDM device into device list.

  @param[in]  SpdmContext       The SPDM context for the device.
**/
VOID
RecordSpdmDeviceInAuthenticationList (
  IN SPDM_DEVICE_CONTEXT          *SpdmDeviceContext
  )
{
  SpdmDeviceContext->IsDeviceAuthenticated = TRUE;
}

/**
  Check if an SPDM device is recorded in device list.

  @param[in]  SpdmContext       The SPDM context for the device.

  @retval TRUE  The SPDM device is in the list.
  @retval FALSE The SPDM device is NOT in the list.
**/
BOOLEAN
IsSpdmDeviceInAuthenticationList (
  IN SPDM_DEVICE_CONTEXT          *SpdmDeviceContext
  )
{
  return SpdmDeviceContext->IsDeviceAuthenticated;
}

/**
  This function does authentication.

  @param[in]  SpdmDeviceContext           The SPDM context for the device.
  @param[out]  AuthState                  The auth state of the devices.
  @param[in]  ValidSlotId                 The number of slot for the certificate chain.
  @param[in]  IsValidCertChain            Indicate the validity of CertChain
  @param[in]  RootCertMatch               Indicate the match or mismatch for Rootcert
  @param[out]  SecurityState              The security state of the requester.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_OUT_OF_RESOURCES  Out of memory.
  @retval EFI_DEVICE_ERROR      The operation was unsuccessful.

**/
EFI_STATUS
EFIAPI
DoDeviceAuthentication (
  IN  SPDM_DEVICE_CONTEXT          *SpdmDeviceContext,
  OUT UINT8                        *AuthState,
  IN  UINT8                        ValidSlotId,
  IN  BOOLEAN                      IsValidCertChain,
  IN  BOOLEAN                      RootCertMatch,
  OUT EDKII_DEVICE_SECURITY_STATE  *SecurityState
  )
{
  SPDM_RETURN          SpdmReturn;
  VOID                 *SpdmContext;
  UINT32               CapabilityFlags;
  UINTN                DataSize;
  SPDM_DATA_PARAMETER  Parameter;
  UINTN                CertChainSize;
  UINT8                CertChain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
  UINT8                RequesterNonce[SPDM_NONCE_SIZE];
  UINT8                ResponderNonce[SPDM_NONCE_SIZE];
  VOID                 *TrustAnchor;
  UINTN                TrustAnchorSize;
  BOOLEAN              IsValidChallengeAuthSig;

  SpdmContext = SpdmDeviceContext->SpdmContext;

  SecurityState->MeasurementState = EDKII_DEVICE_SECURITY_STATE_SUCCESS;
  if (IsSpdmDeviceInAuthenticationList (SpdmDeviceContext)) {
    SecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_SUCCESS;
    return EFI_SUCCESS;
  }

  ZeroMem (&Parameter, sizeof (Parameter));
  Parameter.location = SpdmDataLocationConnection;
  DataSize           = sizeof (CapabilityFlags);
  SpdmReturn         = SpdmGetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &CapabilityFlags, &DataSize);
  if (LIBSPDM_STATUS_IS_ERROR (SpdmReturn)) {
    SecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_ERROR_DEVICE_ERROR;
    return EFI_DEVICE_ERROR;
  }

  IsValidChallengeAuthSig = FALSE;

  // get the valid CertChain
  CertChainSize = sizeof (CertChain);
  ZeroMem (CertChain, sizeof (CertChain));
  SpdmReturn = SpdmGetCertificateEx (SpdmContext, NULL, ValidSlotId, &CertChainSize, CertChain, (CONST VOID **)&TrustAnchor, &TrustAnchorSize);
  if ((!LIBSPDM_STATUS_IS_SUCCESS (SpdmReturn)) && (!(SpdmReturn == LIBSPDM_STATUS_VERIF_NO_AUTHORITY))) {
    return EFI_DEVICE_ERROR;
  }

  if ((CapabilityFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) == 0) {
    *AuthState                         = TCG_DEVICE_SECURITY_EVENT_DATA_DEVICE_AUTH_STATE_NO_BINDING;
    SecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_ERROR_DEVICE_NO_CAPABILITIES;
    return EFI_SUCCESS;
  } else {
    ZeroMem (RequesterNonce, sizeof (RequesterNonce));
    ZeroMem (ResponderNonce, sizeof (ResponderNonce));
    SpdmReturn = SpdmChallengeEx (SpdmContext, NULL, ValidSlotId, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, NULL, NULL, NULL, RequesterNonce, ResponderNonce, NULL, 0);
    if (SpdmReturn == LIBSPDM_STATUS_SUCCESS) {
      IsValidChallengeAuthSig = TRUE;
    } else if ((LIBSPDM_STATUS_IS_ERROR (SpdmReturn))) {
      IsValidChallengeAuthSig            = FALSE;
      *AuthState                         = TCG_DEVICE_SECURITY_EVENT_DATA_DEVICE_AUTH_STATE_FAIL_INVALID;
      SecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_ERROR_CHALLENGE_FAILURE;
      return EFI_SUCCESS;
    } else {
      return EFI_DEVICE_ERROR;
    }

    if (IsValidCertChain && IsValidChallengeAuthSig && !RootCertMatch) {
      *AuthState                         = TCG_DEVICE_SECURITY_EVENT_DATA_DEVICE_AUTH_STATE_NO_AUTH;
      SecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_ERROR_NO_CERT_PROVISION;
    } else if (IsValidCertChain && IsValidChallengeAuthSig && RootCertMatch) {
      *AuthState                         = TCG_DEVICE_SECURITY_EVENT_DATA_DEVICE_AUTH_STATE_SUCCESS;
      SecurityState->AuthenticationState = EDKII_DEVICE_SECURITY_STATE_SUCCESS;
    }
  }

  if (SecurityState->AuthenticationState == EDKII_DEVICE_SECURITY_STATE_SUCCESS) {
    RecordSpdmDeviceInAuthenticationList (SpdmDeviceContext);
  }

  return EFI_SUCCESS;
}
