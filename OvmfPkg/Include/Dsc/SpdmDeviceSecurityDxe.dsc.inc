[Components]
!if $(LIBSPDM_ENABLE) == TRUE
  DeviceSecurityPkg/DeployCert/DeployCert.inf
  DeviceSecurityPkg/SpdmDeviceSecurityDxe/SpdmDeviceSecurityDxe.inf {
    <LibraryClasses>
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
  }
!endif
