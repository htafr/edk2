##
#    SPDX-License-Identifier: BSD-2-Clause-Patent
##

!if $(TPM2_ENABLE) == TRUE
  OvmfPkg/Tcg/TpmMmioSevDecryptPei/TpmMmioSevDecryptPei.inf
!if $(TPM1_ENABLE) == TRUE
  OvmfPkg/Tcg/Tcg2Config/Tcg12ConfigPei.inf
  SecurityPkg/Tcg/TcgPei/TcgPei.inf
!else
  OvmfPkg/Tcg/Tcg2Config/Tcg2ConfigPei.inf
!endif
  SecurityPkg/Tcg/Tcg2Pei/Tcg2Pei.inf {
    <LibraryClasses>
      Tpm2DeviceLib|SecurityPkg/Library/Tpm2DeviceLibRouter/Tpm2DeviceLibRouterPei.inf
      NULL|SecurityPkg/Library/Tpm2DeviceLibDTpm/Tpm2InstanceLibDTpm.inf
      HashLib|SecurityPkg/Library/HashLibBaseCryptoRouter/HashLibBaseCryptoRouterPei.inf
      NULL|SecurityPkg/Library/HashInstanceLibSha1/HashInstanceLibSha1.inf
      NULL|SecurityPkg/Library/HashInstanceLibSha256/HashInstanceLibSha256.inf
      NULL|SecurityPkg/Library/HashInstanceLibSha384/HashInstanceLibSha384.inf
      NULL|SecurityPkg/Library/HashInstanceLibSha512/HashInstanceLibSha512.inf
      NULL|SecurityPkg/Library/HashInstanceLibSm3/HashInstanceLibSm3.inf
      NULL|SecurityPkg/DeviceSecurity/PeiSpdmSecurityLib/PeiSpdmSecurityLib.inf
      SpdmDeviceSecretLib|SecurityPkg/DeviceSecurity/SpdmLib/PeiSpdmDeviceSecretLibSample.inf
      SpdmCryptLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmCryptLib.inf
      SpdmCommonLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmCommonLib.inf
      SpdmRequesterLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmRequesterLib.inf
      SpdmResponderLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmResponderLib.inf
      SpdmSecuredMessageLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmSecuredMessageLib.inf
      SpdmTransportMctpLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmTransportMctpLib.inf
      SpdmTransportPciDoeLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmTransportPciDoeLib.inf

      CryptlibWrapper|SecurityPkg/DeviceSecurity/OsStub/CryptlibWrapper/CryptlibWrapper.inf
      PlatformLibWrapper|SecurityPkg/DeviceSecurity/OsStub/PlatformLibWrapper/PlatformLibWrapper.inf
      MemLibWrapper|SecurityPkg/DeviceSecurity/OsStub/MemLibWrapper/MemLibWrapper.inf
  }
  SecurityPkg/Tcg/Tcg2PlatformPei/Tcg2PlatformPei.inf {
    <LibraryClasses>
      TpmPlatformHierarchyLib|SecurityPkg/Library/PeiDxeTpmPlatformHierarchyLib/PeiDxeTpmPlatformHierarchyLib.inf
  }
!endif
