/** @file
  EDKII DeployCert

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <hal/base.h>
#include <IndustryStandard/UefiTcgPlatform.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/TpmMeasurementLib.h>
#include <Guid/DeviceAuthentication.h>
#include <Guid/ImageAuthentication.h>
#include <Stub/SpdmLibStub.h>
#include <industry_standard/spdm.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiLib.h>
#include "DeployCert.h"

#define SHA256_HASH_SIZE  32
#define SHA384_HASH_SIZE  48
#define SHA512_HASH_SIZE  64

#define TEST_CONFIG_NO_CONFIG                         0
#define TEST_CONFIG_NO_CERT_CAP                       1
#define TEST_CONFIG_NO_CHAL_CAP                       2
#define TEST_CONFIG_INVALID_CERT_CHAIN                3
#define TEST_CONFIG_INVALID_CHALLENGE_AUTH_SIGNATURE  4
#define TEST_CONFIG_INVALID_MEASUREMENT_SIGNATURE     5
#define TEST_CONFIG_MEAS_CAP_NO_SIG                   6
#define TEST_CONFIG_NO_MEAS_CAP                       7
#define TEST_CONFIG_NO_TRUST_ANCHOR                   8
#define TEST_CONFIG_SECURITY_POLICY_AUTH_ONLY         9
#define TEST_CONFIG_SECURITY_POLICY_MEAS_ONLY         10
#define TEST_CONFIG_SECURITY_POLICY_NONE              11
#define TEST_CONFIG_MEASUREMENT_CONTENT_MODIFIED      12
#define TEST_CONFIG_RSASSA_3072_SHA_384               13
#define TEST_CONFIG_RSASSA_4096_SHA_512               14
#define TEST_CONFIG_ECDSA_ECC_P256_SHA_256            15
#define TEST_CONFIG_ECDSA_ECC_P384_SHA_384            16
#define TEST_CONFIG_ECDSA_ECC_P521_SHA_512            17
#define TEST_CONFIG_SECP_256_R1_AES_256_GCM           18
#define TEST_CONFIG_SECP_521_R1_CHACHA20_POLY1305     19
#define TEST_CONFIG_NO_CHAL_CAP_NO_ROOT_CA            20
#define TEST_CONFIG_MULTIPLE_CERT_IN_DB               21
#define TEST_CONFIG_DIFF_CERT_IN_DIFF_SLOT            22
#define TEST_CONFIG_NO_EFI_CERT_X509_GUID_IN_DB       23
#define TEST_CONFIG_SPDM_MESSAGE_VERSION_11           24
#define TEST_CONFIG_SPDM_MESSAGE_VERSION_10           25

extern UINT8  TestRootKey[];
extern UINTN  TestRootKeySize;

extern UINT8  ResponderPublicCertificateChainHash[];
extern UINTN  ResponderPublicCertificateChainHashSize;

extern UINT8  RequesterPublicCertificateChainData[];
extern UINTN  RequesterPublicCertificateChainDataSize;

SHELL_PARAM_ITEM  mParamList[] = {
  { L"-P", TypeFlag  },
  { L"-T", TypeValue },
  { NULL,  TypeMax   },
};

typedef BOOLEAN (EFIAPI *ShaHashAllFunc)(
  CONST VOID  *Data,
  UINTN       DataSize,
  UINT8       *HashValue
  );

//*
EFI_STATUS
EFIAPI
MeasureVariable (
  IN      UINT32    PcrIndex,
  IN      UINT32    EventType,
  IN      CHAR16    *VarName,
  IN      EFI_GUID  *VendorGuid,
  IN      VOID      *VarData,
  IN      UINTN     VarSize
  )
{
  EFI_STATUS          Status;
  UINTN               VarNameLength;
  UEFI_VARIABLE_DATA  *VarLog;
  UINT32              VarLogSize;

  ASSERT ((VarSize == 0 && VarData == NULL) || (VarSize != 0 && VarData != NULL));

  VarNameLength = StrLen (VarName);
  VarLogSize    = (UINT32)(sizeof (*VarLog) + VarNameLength * sizeof (*VarName) + VarSize
                           - sizeof (VarLog->UnicodeName) - sizeof (VarLog->VariableData));

  VarLog = (UEFI_VARIABLE_DATA *)AllocateZeroPool (VarLogSize);
  if (VarLog == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (&VarLog->VariableName, VendorGuid, sizeof (VarLog->VariableName));
  VarLog->UnicodeNameLength  = VarNameLength;
  VarLog->VariableDataLength = VarSize;
  CopyMem (
    VarLog->UnicodeName,
    VarName,
    VarNameLength * sizeof (*VarName)
    );
  if (VarSize != 0) {
    CopyMem (
      (CHAR16 *)VarLog->UnicodeName + VarNameLength,
      VarData,
      VarSize
      );
  }

  DEBUG ((EFI_D_INFO, "VariableDxe: MeasureVariable (Pcr - %x, EventType - %x, ", (UINTN)7, (UINTN)EV_EFI_SPDM_DEVICE_POLICY));
  DEBUG ((EFI_D_INFO, "VariableName - %s, VendorGuid - %g)\n", VarName, VendorGuid));

  Status = TpmMeasureAndLogData (
             PcrIndex,
             EventType,
             VarLog,
             VarLogSize,
             VarLog,
             VarLogSize
             );
  FreePool (VarLog);
  return Status;
}

EFI_STATUS
EFIAPI
DeleteNvIndex (
  UINT32  Index
  )
{
  EFI_STATUS  Status;

  Status = Tpm2NvUndefineSpace (TPM_RH_OWNER, Index, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Delete TPM NV index failed, Index: %x, Status: %r\n", Index, Status));
  }

  return Status;
}

EFI_STATUS
EFIAPI
CreateNvIndex (
  TPMI_RH_NV_INDEX  NvIndex,
  TPMI_ALG_HASH     HashAlg
  )
{
  EFI_STATUS         Status;
  TPMI_RH_PROVISION  AuthHandle;
  TPM2B_NV_PUBLIC    PublicInfo;
  TPM2B_AUTH         NullAuth;
  TPM2B_NAME         PubName;
  UINT16             DataSize;

  Status = Tpm2NvReadPublic (NvIndex, &PublicInfo, &PubName);
  if ((Status != EFI_SUCCESS) && (Status != EFI_NOT_FOUND)) {
    DEBUG ((DEBUG_ERROR, "%a - Failed to read the index! %r\n", __FUNCTION__, Status));
    Status = EFI_DEVICE_ERROR;
    return Status;
  }

  if (Status == EFI_SUCCESS) {
    // Already defined, do nothing
    Status = EFI_ALREADY_STARTED;
    return Status;
  }

  DataSize = GetHashSizeFromAlgo (HashAlg);

  ZeroMem (&PublicInfo, sizeof (PublicInfo));
  PublicInfo.size = sizeof (TPMI_RH_NV_INDEX) +
                    sizeof (TPMI_ALG_HASH) +
                    sizeof (TPMA_NV) +
                    sizeof (UINT16) +
                    sizeof (UINT16);

  PublicInfo.nvPublic.nvIndex                           = NvIndex;
  PublicInfo.nvPublic.nameAlg                           = HashAlg;
  PublicInfo.nvPublic.authPolicy.size                   = 0;
  PublicInfo.nvPublic.dataSize                          = DataSize;
  PublicInfo.nvPublic.attributes.TPMA_NV_PPWRITE        = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_EXTEND         = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_WRITEALL       = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_PPREAD         = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_OWNERREAD      = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_AUTHREAD       = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_POLICYREAD     = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_NO_DA          = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_ORDERLY        = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_CLEAR_STCLEAR  = 1;
  PublicInfo.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;

  AuthHandle = TPM_RH_PLATFORM;
  ZeroMem (&NullAuth, sizeof (NullAuth));

  return Tpm2NvDefineSpace (
           AuthHandle,
           NULL,
           &NullAuth,
           &PublicInfo
           );
}

EFI_STATUS
EFIAPI
ProvisionNvIndex (
  VOID
  )
{
  EFI_STATUS        Status;
  UINT16            DataSize;
  TPMI_RH_NV_AUTH   AuthHandle;
  UINT16            Offset;
  TPM2B_MAX_BUFFER  OutData;
  UINT16            Index;

  Status = CreateNvIndex (
             TCG_NV_EXTEND_INDEX_FOR_INSTANCE,
             TPM_ALG_SHA256
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "CreateNvIndex (INSTANCE) Status- %r\n", Status));
  }

  Status = CreateNvIndex (
             TCG_NV_EXTEND_INDEX_FOR_DYNAMIC,
             TPM_ALG_SHA256
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "CreateNvIndex (DYNAMIC) Status- %r\n", Status));
  }

  DataSize = GetHashSizeFromAlgo (TPM_ALG_SHA256);
  Offset   = 0;

  AuthHandle = TPM_RH_PLATFORM;
  ZeroMem (&OutData, sizeof (OutData));
  Status = Tpm2NvRead (
             AuthHandle,
             TCG_NV_EXTEND_INDEX_FOR_INSTANCE,
             NULL,
             DataSize,
             Offset,
             &OutData
             );
  if (Status == EFI_SUCCESS) {
    DEBUG ((DEBUG_ERROR, "NvIndex 0x%x\n", TCG_NV_EXTEND_INDEX_FOR_INSTANCE));
    DEBUG ((DEBUG_ERROR, "Data Size: 0x%x\n", OutData.size));
    for (Index = 0; Index < OutData.size; Index++ ) {
      DEBUG ((DEBUG_ERROR, "%02x", OutData.buffer[Index]));
    }

    DEBUG ((DEBUG_ERROR, "\n"));
  }

  ZeroMem (&OutData, sizeof (OutData));
  Status = Tpm2NvRead (
             AuthHandle,
             TCG_NV_EXTEND_INDEX_FOR_DYNAMIC,
             NULL,
             DataSize,
             Offset,
             &OutData
             );
  if (Status == EFI_SUCCESS) {
    DEBUG ((DEBUG_ERROR, "NvIndex 0x%x\n", TCG_NV_EXTEND_INDEX_FOR_DYNAMIC));
    DEBUG ((DEBUG_ERROR, "Data Size: 0x%x\n", OutData.size));
    for (Index = 0; Index < OutData.size; Index++ ) {
      DEBUG ((DEBUG_ERROR, "%02x", OutData.buffer[Index]));
    }

    DEBUG ((DEBUG_ERROR, "\n"));
  }

  return Status;
}
//*/

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
MainEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS          Status;
  SPDM_CERT_CHAIN     *RequesterCertChain;
  UINTN               RequesterCertChainSize;
  UINT8               *CertChain;
  UINTN               CertChainSize;
  EFI_SIGNATURE_LIST  *SignatureList;
  EFI_SIGNATURE_LIST  *DbList;
  EFI_SIGNATURE_DATA  *CertData;
  UINTN               SignatureListSize;
  UINTN               SignatureHeaderSize;
  UINTN               DbSize;
  UINT8               *RootCert;
  UINTN               RootCertSize;
  UINTN               HashSize;
  UINT8               *RootKey;
  UINTN               RootKeySize;

  Status = ProvisionNvIndex ();
  DEBUG ((DEBUG_INFO, "%a: ProvisionNvIndex - %r\n", __func__, Status));

  DEBUG ((DEBUG_INFO, "[EDKII @ %a]: Deploying certificates...\n", __func__));

  CertChain     = RequesterPublicCertificateChainData;
  CertChainSize = RequesterPublicCertificateChainDataSize;
  HashSize      = SHA384_HASH_SIZE;
  RootKey       = TestRootKey;
  RootKeySize   = TestRootKeySize;
  RootCert      = ResponderPublicCertificateChainHash;
  RootCertSize  = ResponderPublicCertificateChainHashSize;

  //
  // In this test config, The database has two signature lists.
  // The first one contains two siganture data for two root certs.
  // The second one contains one signature data for one root cert
  // which matches the cert chain of the responder.
  //
  SignatureHeaderSize = 0;
  DbSize = sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + 2 * (sizeof (EFI_GUID) + RootCertSize);
  DbList        = AllocateZeroPool (DbSize);
  ASSERT (DbList != NULL);
  SignatureList = DbList;
  SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + 2 * (sizeof (EFI_GUID) + RootCertSize);
  CopyGuid (&SignatureList->SignatureType, &gEfiCertX509Guid);
  SignatureList->SignatureListSize   = (UINT32)SignatureListSize;
  SignatureList->SignatureHeaderSize = (UINT32)SignatureHeaderSize;
  SignatureList->SignatureSize       = (UINT32)(sizeof (EFI_GUID) + RootCertSize);
  CertData                           = (EFI_SIGNATURE_DATA *)((UINT8 *)SignatureList + sizeof (EFI_SIGNATURE_LIST));
  CopyGuid (&CertData->SignatureOwner, &gEfiCallerIdGuid);
  CopyMem (
    (UINT8 *)CertData->SignatureData,
    RootCert,
    RootCertSize
    );
  CertData = (EFI_SIGNATURE_DATA *)((UINT8 *)CertData + SignatureList->SignatureSize);
  CopyGuid (&CertData->SignatureOwner, &gEfiCallerIdGuid);
  CopyMem (
    (UINT8 *)CertData->SignatureData,
    RootCert,
    RootCertSize
    );

  /*
  RootCert = TestRootCer;
  RootCertSize = TestRootCerSize;
  SignatureList  = (EFI_SIGNATURE_LIST *)((UINT8 *)SignatureList + SignatureList->SignatureListSize);
  SignatureListSize = sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + sizeof (EFI_GUID) + RootCertSize;
  CopyGuid (&SignatureList->SignatureType, &gEfiCertX509Guid);
  SignatureList->SignatureListSize   = (UINT32)SignatureListSize;
  SignatureList->SignatureHeaderSize = (UINT32)SignatureHeaderSize;
  SignatureList->SignatureSize       = (UINT32)(sizeof (EFI_GUID) + RootCertSize);
  CertData                           = (EFI_SIGNATURE_DATA *)((UINT8 *)SignatureList + sizeof (EFI_SIGNATURE_LIST));
  CopyGuid (&CertData->SignatureOwner, &gEfiCallerIdGuid);
  CopyMem (
    (UINT8 *)CertData->SignatureData,
    RootCert,
    RootCertSize
    );
  //*/

  /*
  else if (TestConfig == TEST_CONFIG_NO_EFI_CERT_X509_GUID_IN_DB) {
    SignatureHeaderSize = 0;
    DbSize   = sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + sizeof (EFI_GUID) + RootCertSize;
    DbList   = AllocateZeroPool (DbSize);
    SignatureList = DbList;
    SignatureListSize = DbSize;
    ASSERT (SignatureList != NULL);
    // Here the SignatureType is gEfiCertSha256Guid, not gEfiCertX509Guid.
    CopyGuid (&SignatureList->SignatureType, &gEfiCertSha256Guid);
    SignatureList->SignatureListSize   = (UINT32)SignatureListSize;
    SignatureList->SignatureHeaderSize = (UINT32)SignatureHeaderSize;
    SignatureList->SignatureSize       = (UINT32)(sizeof (EFI_GUID) + RootCertSize);
    CertData                           = (VOID *)((UINT8 *)SignatureList + sizeof (EFI_SIGNATURE_LIST));
    CopyGuid (&CertData->SignatureOwner, &gEfiCallerIdGuid);
    CopyMem (
      (UINT8 *)SignatureList + sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + sizeof (EFI_GUID),
      RootCert,
      RootCertSize
      );
  } else {
    SignatureHeaderSize = 0;
    DbSize   = sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + sizeof (EFI_GUID) + RootCertSize;
    DbList   = AllocateZeroPool (DbSize);
    SignatureList = DbList;
    SignatureListSize = DbSize;
    ASSERT (SignatureList != NULL);
    CopyGuid (&SignatureList->SignatureType, &gEfiCertX509Guid);
    SignatureList->SignatureListSize   = (UINT32)SignatureListSize;
    SignatureList->SignatureHeaderSize = (UINT32)SignatureHeaderSize;
    SignatureList->SignatureSize       = (UINT32)(sizeof (EFI_GUID) + RootCertSize);
    CertData                           = (VOID *)((UINT8 *)SignatureList + sizeof (EFI_SIGNATURE_LIST));
    CopyGuid (&CertData->SignatureOwner, &gEfiCallerIdGuid);
    CopyMem (
      (UINT8 *)SignatureList + sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + sizeof (EFI_GUID),
      RootCert,
      RootCertSize
      );
  }
  //*/
  Status = gRT->SetVariable (
                  EFI_DEVICE_SECURITY_DATABASE,
                  &gEfiDeviceSignatureDatabaseGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  DbSize,
                  (VOID *)DbList
                  );
  ASSERT_EFI_ERROR (Status);
  FreePool (DbList);

  RequesterCertChainSize = sizeof (SPDM_CERT_CHAIN) + HashSize + CertChainSize;
  RequesterCertChain     = AllocateZeroPool (RequesterCertChainSize);
  ASSERT (RequesterCertChain != NULL);
  RequesterCertChain->Length   = (UINT16)RequesterCertChainSize;
  RequesterCertChain->Reserved = 0;
  /*
  if (TestConfig != TEST_CONFIG_INVALID_CERT_CHAIN) {
    if (TestConfig == TEST_CONFIG_NO_TRUST_ANCHOR) {
      ShaHashAll (TestRootCer2, TestRootCer2Size, (VOID *)(ResponderCertChain + 1));
    } else {
    }
  }
  //*/

  CopyMem (
    (UINT8 *)RequesterCertChain + sizeof (SPDM_CERT_CHAIN) + HashSize,
    CertChain,
    CertChainSize
    );

  Status = gRT->SetVariable (
                  L"RequesterSpdmCertChain",
                  &gEfiDeviceSecurityConfig,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  RequesterCertChainSize,
                  RequesterCertChain
                  );
  ASSERT_EFI_ERROR (Status);
  FreePool (RequesterCertChain);

  {
    //
    // TBD - we need only include the root-cert, instead of the CertChain
    // BUGBUG: Hardcode here to pass measurement at first
    //
    SignatureHeaderSize = 0;
    SignatureListSize   = sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + sizeof (EFI_GUID) + RootCertSize;
    SignatureList       = AllocateZeroPool (SignatureListSize);
    ASSERT (SignatureList != NULL);
    CopyGuid (&SignatureList->SignatureType, &gEfiCertX509Guid);
    SignatureList->SignatureListSize   = (UINT32)SignatureListSize;
    SignatureList->SignatureHeaderSize = (UINT32)SignatureHeaderSize;
    SignatureList->SignatureSize       = (UINT32)(sizeof (EFI_GUID) + RootCertSize);
    CertData                           = (VOID *)((UINT8 *)SignatureList + sizeof (EFI_SIGNATURE_LIST));
    CopyGuid (&CertData->SignatureOwner, &gEfiCallerIdGuid);
    CopyMem (
      (UINT8 *)SignatureList + sizeof (EFI_SIGNATURE_LIST) + SignatureHeaderSize + sizeof (EFI_GUID),
      RootCert,
      RootCertSize
      );

    MeasureVariable (
      PCR_INDEX_FOR_SIGNATURE_DB,
      EV_EFI_SPDM_DEVICE_POLICY,
      EFI_DEVICE_SECURITY_DATABASE,
      &gEfiDeviceSignatureDatabaseGuid,
      SignatureList,
      SignatureListSize
      );
    FreePool (SignatureList);
  }

  Status = gRT->SetVariable (
                  L"PrivDevKey",
                  &gEfiDeviceSignatureDatabaseGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  RootKeySize,
                  RootKey
                  );

  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}
