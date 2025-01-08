[BuildOptions]
!if $(LIBSPDM_ENABLE) == TRUE
  GCC:*_*_*_CC_FLAGS = -DLIBSPDM_ENABLE=1
!endif

[LibraryClasses]
!if $(LIBSPDM_ENABLE) == TRUE
  SpdmSecurityLib|SecurityPkg/DeviceSecurity/SpdmSecurityLib/SpdmSecurityLib.inf
  SpdmDeviceSecretLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmDeviceSecretLibNull.inf
  SpdmCryptLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmCryptLib.inf
  SpdmCommonLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmCommonLib.inf
  SpdmRequesterLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmRequesterLib.inf
  SpdmResponderLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmResponderLib.inf
  SpdmSecuredMessageLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmSecuredMessageLib.inf
  SpdmTransportMctpLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmTransportMctpLib.inf
  SpdmTransportPciDoeLib|SecurityPkg/DeviceSecurity/SpdmLib/SpdmTransportPciDoeLib.inf
  SpdmMeasurementLib|SecurityPkg/DeviceSecurity/SpdmSecurityLib/SpdmSecurityLib.inf

  CryptlibWrapper|SecurityPkg/DeviceSecurity/OsStub/CryptlibWrapper/CryptlibWrapper.inf
  PlatformLibWrapper|SecurityPkg/DeviceSecurity/OsStub/PlatformLibWrapper/PlatformLibWrapper.inf
  MemLibWrapper|SecurityPkg/DeviceSecurity/OsStub/MemLibWrapper/MemLibWrapper.inf
!endif

[Components]
!if $(LIBSPDM_ENABLE) == TRUE
  OvmfPkg/DeployCert/DeployCert.inf
  OvmfPkg/SpdmDeviceSecurityDxe/SpdmDeviceSecurityDxe.inf
!endif
