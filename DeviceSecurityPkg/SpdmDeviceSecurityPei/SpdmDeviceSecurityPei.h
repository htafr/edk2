#ifndef __SPDM_DEVICE_SECURITY_PEI_H__
#define __SPDM_DEVICE_SECURITY_PEI_H__

#include <hal/base.h>
#include <Stub/SpdmLibStub.h>
#include <industry_standard/spdm.h>
#include <industry_standard/spdm_secured_message.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <library/spdm_transport_pcidoe_lib.h>
#include <Guid/DeviceAuthentication.h>
#include <Guid/ImageAuthentication.h>
#include <IndustryStandard/Pci.h>
#include <IndustryStandard/Tpm20.h>
#include <IndustryStandard/UefiTcgPlatform.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PeiServicesLib.h>
#include <Library/PeiServicesTablePointerLib.h>
#include <Library/RngLib.h>
#include <Library/TpmMeasurementLib.h>
#include <PiPei.h>
#include <Ppi/DeviceSecurity.h>
#include <Ppi/DeviceSecurityPolicy.h>
#include <Ppi/ReadOnlyVariable2.h>

#endif
