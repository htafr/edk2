/** @file
  TIS (TPM Interface Specification) functions used by dTPM2.0 library.

Copyright (c) 2013 - 2018, Intel Corporation. All rights reserved.<BR>
(C) Copyright 2015 Hewlett Packard Enterprise Development LP<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <IndustryStandard/Tpm20.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/IoLib.h>
#include <Library/TimerLib.h>
#include <Library/DebugLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/PcdLib.h>

#include "Tpm2Spdm.h"

#include <IndustryStandard/TpmTis.h>

#define TIS_TIMEOUT_MAX  (90000 * 1000)             // 90s

//
// Max TPM command/response length
//
#define TPMCMDBUFLENGTH  0x500

BOOLEAN mSendReceiveBufferAcquired = FALSE;
VOID    *SpdmMsgBuffer;

/**
  Check whether TPM chip exist.

  @param[in] TisReg  Pointer to TIS register.

  @retval    TRUE    TPM chip exists.
  @retval    FALSE   TPM chip is not found.
**/
BOOLEAN
TisPcPresenceCheck (
  IN      TIS_PC_REGISTERS_PTR  TisReg
  )
{
  UINT8  RegRead;

  RegRead = MmioRead8 ((UINTN)&TisReg->Access);
  return (BOOLEAN)(RegRead != (UINT8)-1);
}

/**
  Check whether the value of a TPM chip register satisfies the input BIT setting.

  @param[in]  Register     Address port of register to be checked.
  @param[in]  BitSet       Check these data bits are set.
  @param[in]  BitClear     Check these data bits are clear.
  @param[in]  TimeOut      The max wait time (unit MicroSecond) when checking register.

  @retval     EFI_SUCCESS  The register satisfies the check bit.
  @retval     EFI_TIMEOUT  The register can't run into the expected status in time.
**/
EFI_STATUS
TisPcWaitRegisterBits (
  IN      UINT8   *Register,
  IN      UINT8   BitSet,
  IN      UINT8   BitClear,
  IN      UINT32  TimeOut
  )
{
  UINT8   RegRead;
  UINT32  WaitTime;

  for (WaitTime = 0; WaitTime < TimeOut; WaitTime += 30) {
    RegRead = MmioRead8 ((UINTN)Register);
    if (((RegRead & BitSet) == BitSet) && ((RegRead & BitClear) == 0)) {
      return EFI_SUCCESS;
    }

    MicroSecondDelay (30);
  }

  return EFI_TIMEOUT;
}

/**
  Get BurstCount by reading the burstCount field of a TIS register
  in the time of default TIS_TIMEOUT_D.

  @param[in]  TisReg                Pointer to TIS register.
  @param[out] BurstCount            Pointer to a buffer to store the got BurstCount.

  @retval     EFI_SUCCESS           Get BurstCount.
  @retval     EFI_INVALID_PARAMETER TisReg is NULL or BurstCount is NULL.
  @retval     EFI_TIMEOUT           BurstCount can't be got in time.
**/
EFI_STATUS
TisPcReadBurstCount (
  IN      TIS_PC_REGISTERS_PTR  TisReg,
  OUT  UINT16                   *BurstCount
  )
{
  UINT32  WaitTime;
  UINT8   DataByte0;
  UINT8   DataByte1;

  if ((BurstCount == NULL) || (TisReg == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  WaitTime = 0;
  do {
    //
    // TIS_PC_REGISTERS_PTR->burstCount is UINT16, but it is not 2bytes aligned,
    // so it needs to use MmioRead8 to read two times
    //
    DataByte0   = MmioRead8 ((UINTN)&TisReg->BurstCount);
    DataByte1   = MmioRead8 ((UINTN)&TisReg->BurstCount + 1);
    *BurstCount = (UINT16)((DataByte1 << 8) + DataByte0);
    if (*BurstCount != 0) {
      return EFI_SUCCESS;
    }

    MicroSecondDelay (30);
    WaitTime += 30;
  } while (WaitTime < TIS_TIMEOUT_D);

  return EFI_TIMEOUT;
}

/**
  Set TPM chip to ready state by sending ready command TIS_PC_STS_READY
  to Status Register in time.

  @param[in] TisReg                Pointer to TIS register.

  @retval    EFI_SUCCESS           TPM chip enters into ready state.
  @retval    EFI_INVALID_PARAMETER TisReg is NULL.
  @retval    EFI_TIMEOUT           TPM chip can't be set to ready state in time.
**/
EFI_STATUS
TisPcPrepareCommand (
  IN      TIS_PC_REGISTERS_PTR  TisReg
  )
{
  EFI_STATUS  Status;

  if (TisReg == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  MmioWrite8 ((UINTN)&TisReg->Status, TIS_PC_STS_READY);
  Status = TisPcWaitRegisterBits (
             &TisReg->Status,
             TIS_PC_STS_READY,
             0,
             TIS_TIMEOUT_B
             );
  return Status;
}

/**
  Send a command to TPM for execution and return response data.

  @param[in]      TisReg        TPM register space base address.
  @param[in]      BufferIn      Buffer for command data.
  @param[in]      SizeIn        Size of command data.
  @param[in, out] BufferOut     Buffer for response data.
  @param[in, out] SizeOut       Size of response data.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_BUFFER_TOO_SMALL  Response data buffer is too small.
  @retval EFI_DEVICE_ERROR      Unexpected device behavior.
  @retval EFI_UNSUPPORTED       Unsupported TPM version

**/
EFI_STATUS
Tpm2TisTpmCommand (
  IN     TIS_PC_REGISTERS_PTR  TisReg,
  IN     UINT8                 *BufferIn,
  IN     UINT32                SizeIn,
  IN OUT UINT8                 *BufferOut,
  IN OUT UINT32                *SizeOut
  )
{
  EFI_STATUS  Status;
  UINT16      BurstCount;
  UINT32      Index;
  UINT32      TpmOutSize;
  UINT16      Data16;
  UINT32      Data32;

  DEBUG_CODE_BEGIN ();
  UINTN  DebugSize;

  DEBUG ((DEBUG_VERBOSE, "Tpm2TisTpmCommand Send - "));
  if (SizeIn > 0x100) {
    DebugSize = 0x40;
  } else {
    DebugSize = SizeIn;
  }

  for (Index = 0; Index < DebugSize; Index++) {
    DEBUG ((DEBUG_VERBOSE, "%02x ", BufferIn[Index]));
  }

  if (DebugSize != SizeIn) {
    DEBUG ((DEBUG_VERBOSE, "...... "));
    for (Index = SizeIn - 0x20; Index < SizeIn; Index++) {
      DEBUG ((DEBUG_VERBOSE, "%02x ", BufferIn[Index]));
    }
  }

  DEBUG ((DEBUG_VERBOSE, "\n"));
  DEBUG_CODE_END ();
  TpmOutSize = 0;

  Status = TisPcPrepareCommand (TisReg);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Tpm2 is not ready for command!\n"));
    return EFI_DEVICE_ERROR;
  }

  //
  // Send the command data to Tpm
  //
  Index = 0;
  while (Index < SizeIn) {
    Status = TisPcReadBurstCount (TisReg, &BurstCount);
    if (EFI_ERROR (Status)) {
      Status = EFI_DEVICE_ERROR;
      goto Exit;
    }

    for ( ; BurstCount > 0 && Index < SizeIn; BurstCount--) {
      MmioWrite8 ((UINTN)&TisReg->DataFifo, *(BufferIn + Index));
      Index++;
    }
  }

  //
  // Check the Tpm status STS_EXPECT change from 1 to 0
  //
  Status = TisPcWaitRegisterBits (
             &TisReg->Status,
             (UINT8)TIS_PC_VALID,
             TIS_PC_STS_EXPECT,
             TIS_TIMEOUT_C
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Tpm2 The send buffer too small!\n"));
    Status = EFI_BUFFER_TOO_SMALL;
    goto Exit;
  }

  //
  // Executed the TPM command and waiting for the response data ready
  //
  MmioWrite8 ((UINTN)&TisReg->Status, TIS_PC_STS_GO);

  //
  // NOTE: That may take many seconds to minutes for certain commands, such as key generation.
  //
  Status = TisPcWaitRegisterBits (
             &TisReg->Status,
             (UINT8)(TIS_PC_VALID | TIS_PC_STS_DATA),
             0,
             TIS_TIMEOUT_MAX
             );
  if (EFI_ERROR (Status)) {
    //
    // dataAvail check timeout. Cancel the currently executing command by writing commandCancel,
    // Expect TPM_RC_CANCELLED or successfully completed response.
    //
    DEBUG ((DEBUG_ERROR, "Wait for Tpm2 response data time out. Trying to cancel the command!!\n"));

    MmioWrite32 ((UINTN)&TisReg->Status, TIS_PC_STS_CANCEL);
    Status = TisPcWaitRegisterBits (
               &TisReg->Status,
               (UINT8)(TIS_PC_VALID | TIS_PC_STS_DATA),
               0,
               TIS_TIMEOUT_B
               );
    //
    // Do not clear CANCEL bit here because Writes of 0 to this bit are ignored
    //
    if (EFI_ERROR (Status)) {
      //
      // Cancel executing command fail to get any response
      // Try to abort the command with write of a 1 to commandReady in Command Execution state
      //
      Status = EFI_DEVICE_ERROR;
      goto Exit;
    }
  }

  //
  // Get response data header
  //
  Index      = 0;
  BurstCount = 0;
  while (Index < sizeof (TPM2_RESPONSE_HEADER)) {
    Status = TisPcReadBurstCount (TisReg, &BurstCount);
    if (EFI_ERROR (Status)) {
      Status = EFI_DEVICE_ERROR;
      goto Exit;
    }

    for ( ; BurstCount > 0; BurstCount--) {
      *(BufferOut + Index) = MmioRead8 ((UINTN)&TisReg->DataFifo);
      Index++;
      if (Index == sizeof (TPM2_RESPONSE_HEADER)) {
        break;
      }
    }
  }

  DEBUG_CODE_BEGIN ();
  DEBUG ((DEBUG_VERBOSE, "Tpm2TisTpmCommand ReceiveHeader - "));
  for (Index = 0; Index < sizeof (TPM2_RESPONSE_HEADER); Index++) {
    DEBUG ((DEBUG_VERBOSE, "%02x ", BufferOut[Index]));
  }

  DEBUG ((DEBUG_VERBOSE, "\n"));
  DEBUG_CODE_END ();
  //
  // Check the response data header (tag,parasize and returncode )
  //
  CopyMem (&Data16, BufferOut, sizeof (UINT16));
  // TPM2 should not use this RSP_COMMAND
  if (SwapBytes16 (Data16) == TPM_ST_RSP_COMMAND) {
    DEBUG ((DEBUG_ERROR, "TPM2: TPM_ST_RSP error - %x\n", TPM_ST_RSP_COMMAND));
    Status = EFI_UNSUPPORTED;
    goto Exit;
  }

  CopyMem (&Data32, (BufferOut + 2), sizeof (UINT32));
  TpmOutSize = SwapBytes32 (Data32);
  if (*SizeOut < TpmOutSize) {
    Status = EFI_BUFFER_TOO_SMALL;
    goto Exit;
  }

  *SizeOut = TpmOutSize;
  //
  // Continue reading the remaining data
  //
  while ( Index < TpmOutSize ) {
    for ( ; BurstCount > 0; BurstCount--) {
      *(BufferOut + Index) = MmioRead8 ((UINTN)&TisReg->DataFifo);
      Index++;
      if (Index == TpmOutSize) {
        Status = EFI_SUCCESS;
        goto Exit;
      }
    }

    Status = TisPcReadBurstCount (TisReg, &BurstCount);
    if (EFI_ERROR (Status)) {
      Status = EFI_DEVICE_ERROR;
      goto Exit;
    }
  }

Exit:
  DEBUG_CODE_BEGIN ();
  DEBUG ((DEBUG_VERBOSE, "Tpm2TisTpmCommand Receive - "));
  for (Index = 0; Index < TpmOutSize; Index++) {
    DEBUG ((DEBUG_VERBOSE, "%02x ", BufferOut[Index]));
  }

  DEBUG ((DEBUG_VERBOSE, "\n"));
  DEBUG_CODE_END ();
  MmioWrite8 ((UINTN)&TisReg->Status, TIS_PC_STS_READY);
  return Status;
}

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
  UINT16                BurstCount;
  UINT32                Index;
  EFI_STATUS            Status;
  TIS_PC_REGISTERS_PTR  TisReg = (TIS_PC_REGISTERS_PTR)(UINTN)PcdGet64 (PcdTpmBaseAddress);


  Status = TisPcPrepareCommand (TisReg);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Tpm2 is not ready for command!\n"));
    return LIBSPDM_STATUS_SEND_FAIL;
  }

  //
  // Send the command data to Tpm
  //
  Index = 0;
  while (Index < MessageSize) {
    Status = TisPcReadBurstCount (TisReg, &BurstCount);
    if (EFI_ERROR (Status)) {
      goto Exit;
    }

    for ( ; BurstCount > 0 && Index < MessageSize; BurstCount--) {
      MmioWrite8 ((UINTN)&TisReg->DataFifo, *((UINT8 *)Message + Index));
      Index++;
    }
  }

  //
  // Check the Tpm status STS_EXPECT change from 1 to 0
  //
  Status = TisPcWaitRegisterBits (
             &TisReg->Status,
             (UINT8)TIS_PC_VALID,
             TIS_PC_STS_EXPECT,
             TIS_TIMEOUT_C
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Tpm2 The send buffer too small!\n"));
    goto Exit;
  }

  //
  // Executed the TPM command and waiting for the response data ready
  //
  MmioWrite8 ((UINTN)&TisReg->Status, TIS_PC_STS_GO);

  return LIBSPDM_STATUS_SUCCESS;

Exit:
  MmioWrite8 ((UINTN)&TisReg->Status, TIS_PC_STS_READY);
  return LIBSPDM_STATUS_SEND_FAIL;
}

SPDM_RETURN
SpdmIoProtocolDeviceReceiveMessage (
  IN      VOID    *SpdmContext,
  IN OUT  UINTN   *MessageSize,
  IN OUT  VOID    **Message,
  IN      UINT64  Timeout
  )
{
  UINT16                Data16;
  UINT16                BurstCount;
  UINT32                Index;
  EFI_STATUS            Status;
  TIS_PC_REGISTERS_PTR  TisReg = (TIS_PC_REGISTERS_PTR)(UINTN)PcdGet64 (PcdTpmBaseAddress);

  //
  // NOTE: That may take many seconds to minutes for certain commands, such as key generation.
  //
  Status = TisPcWaitRegisterBits (
             &TisReg->Status,
             (UINT8)(TIS_PC_VALID | TIS_PC_STS_DATA),
             0,
             TIS_TIMEOUT_MAX
             );
  if (EFI_ERROR (Status)) {
    //
    // dataAvail check timeout. Cancel the currently executing command by writing commandCancel,
    // Expect TPM_RC_CANCELLED or successfully completed response.
    //
    DEBUG ((DEBUG_ERROR, "Wait for Tpm2 response data time out. Trying to cancel the command!!\n"));

    MmioWrite32 ((UINTN)&TisReg->Status, TIS_PC_STS_CANCEL);
    Status = TisPcWaitRegisterBits (
               &TisReg->Status,
               (UINT8)(TIS_PC_VALID | TIS_PC_STS_DATA),
               0,
               TIS_TIMEOUT_B
               );
    //
    // Do not clear CANCEL bit here because Writes of 0 to this bit are ignored
    //
    if (EFI_ERROR (Status)) {
      //
      // Cancel executing command fail to get any response
      // Try to abort the command with write of a 1 to commandReady in Command Execution state
      //
      Status = EFI_DEVICE_ERROR;
      goto Exit;
    }
  }

  //
  // Get response data header
  //
  Index      = 0;
  BurstCount = 0;
  while (Index < sizeof (TPM2_SPDM_HEADER)) {
    Status = TisPcReadBurstCount (TisReg, &BurstCount);
    if (EFI_ERROR (Status)) {
      Status = EFI_DEVICE_ERROR;
      goto Exit;
    }

    for ( ; BurstCount > 0; BurstCount--) {
      *((UINT8 *)*Message + Index) = MmioRead8 ((UINTN)&TisReg->DataFifo);
      Index++;
      if (Index == sizeof (TPM2_SPDM_HEADER)) {
        break;
      }
    }
  }

  //
  // Check the response data header (tag,parasize and returncode )
  //
  CopyMem (&Data16, *Message, sizeof (UINT16));
  // TPM2 should not use this RSP_COMMAND
  if (SwapBytes16 (Data16) == TPM_ST_RSP_COMMAND) {
    DEBUG ((DEBUG_ERROR, "TPM2: TPM_ST_RSP error - %x\n", TPM_ST_RSP_COMMAND));
    goto Exit;
  }

  CopyMem (&*MessageSize, (*Message + sizeof (UINT16)), sizeof (UINT32));
  *MessageSize = SwapBytes32 (*MessageSize);

  //
  // Continue reading the remaining data
  //
  Index = sizeof (TPM2_SPDM_HEADER);
  while ( Index < *MessageSize ) {
    for ( ; BurstCount > 0; BurstCount--) {
      *((UINT8 *)*Message + Index) = MmioRead8 ((UINTN)&TisReg->DataFifo);
      Index++;
      if (Index == *MessageSize) {
        MmioWrite8 ((UINTN)&TisReg->Status, TIS_PC_STS_READY);
        return LIBSPDM_STATUS_SUCCESS;
      }
    }

    Status = TisPcReadBurstCount (TisReg, &BurstCount);
    if (EFI_ERROR (Status)) {
      goto Exit;
    }
  }

  return LIBSPDM_STATUS_SUCCESS;
Exit:
  MmioWrite8 ((UINTN)&TisReg->Status, TIS_PC_STS_READY);
  return LIBSPDM_STATUS_RECEIVE_FAIL;
}

/**
  Authenticate and Measure TPM device

  @param[in] TisReg                Pointer to TIS register.

  @retval    EFI_SUCCESS           Get the control of TPM chip.
  @retval    EFI_INVALID_PARAMETER TisReg is NULL.
  @retval    EFI_NOT_FOUND         TPM chip doesn't exit.
  @retval    EFI_TIMEOUT           Can't get the TPM control in time.
**/
EFI_STATUS
TisPcSpdmTpm (
  IN      TIS_PC_REGISTERS_PTR  TisReg
  )
{
  UINT8                         AuthState;
  UINT8                         SlotId;
  BOOLEAN                       IsValidCertChain;
  BOOLEAN                       RootCertMatch;
  EFI_STATUS                    Status;
  EDKII_SPDM_DEVICE_INFO        SpdmDeviceInfo;
  SPDM_DEVICE_CONTEXT           *SpdmDeviceContext;
  EDKII_DEVICE_SECURITY_STATE   *SecurityState;

  ZeroMem (&SpdmDeviceInfo, sizeof (SpdmDeviceInfo));
  SpdmDeviceInfo.SendMessage                = SpdmIoProtocolDeviceSendMessage;
  SpdmDeviceInfo.ReceiveMessage             = SpdmIoProtocolDeviceReceiveMessage;

  SpdmDeviceInfo.MaxSpdmMsgSize             = LIBSPDM_MAX_SPDM_MSG_SIZE;
  SpdmDeviceInfo.TransportHeaderSize        = LIBSPDM_TPM_TRANSPORT_HEADER_SIZE;
  SpdmDeviceInfo.TransportTailSize          = LIBSPDM_TPM_TRANSPORT_TAIL_SIZE;

  SpdmDeviceInfo.TransportEncodeMessage     = libspdm_transport_tpm_encode_message;
  SpdmDeviceInfo.TransportDecodeMessage     = libspdm_transport_tpm_decode_message;

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
  SpdmDeviceInfo.MeasurementHashAlgo        = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmDeviceInfo.BaseHashAlgo               = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmDeviceInfo.BaseAsymAlgo               = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
  SpdmDeviceInfo.ReqBaseAsymAlgo            = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
  SpdmDeviceInfo.DheAlgo                    = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048;
  SpdmDeviceInfo.AeadAlgo                   = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
                                              SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM;
  SpdmDeviceInfo.KeyScheduleAlgo            = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
  SpdmDeviceInfo.OtherParamsSupport         = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1 |
                                              SPDM_ALGORITHMS_MULTI_KEY_CONN;
  SpdmDeviceInfo.MelSpec                    = SPDM_MEL_SPECIFICATION_DMTF;

  SecurityState = AllocateZeroPool (sizeof (EDKII_DEVICE_SECURITY_STATE));
  SecurityState->Revision              = EDKII_DEVICE_SECURITY_POLICY_REVISION;
  SecurityState->MeasurementState     = 0x0;
  SecurityState->AuthenticationState  = 0x0;
  SpdmDeviceContext = CreateSpdmDeviceContext(&SpdmDeviceInfo, SecurityState);
  if (SpdmDeviceContext == NULL) {
    return EFI_UNSUPPORTED;
  }

  Status           = EFI_SUCCESS;
  AuthState        = TCG_DEVICE_SECURITY_EVENT_DATA_DEVICE_AUTH_STATE_SUCCESS;
  SlotId           = 0;
  IsValidCertChain = FALSE;
  RootCertMatch    = FALSE;
  Status = DoDeviceAuthentication(SpdmDeviceContext, &AuthState, SlotId, IsValidCertChain, RootCertMatch, SecurityState);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DoDeviceAuthentication failed - %r\n", Status));
    goto Ret;
  } else if ((AuthState == TCG_DEVICE_SECURITY_EVENT_DATA_DEVICE_AUTH_STATE_FAIL_NO_SIG) ||
             (AuthState == TCG_DEVICE_SECURITY_EVENT_DATA_DEVICE_AUTH_STATE_FAIL_INVALID))
  {
    goto Ret;
  }

  Status = DoDeviceMeasurement (SpdmDeviceContext, SlotId, SecurityState);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "DoDeviceMeasurement failed - %r\n", Status));
  }


  return EFI_SUCCESS;
Ret:
  DestroySpdmDeviceContext (SpdmDeviceContext);

  return Status;
}


/**
  Get the control of TPM chip by sending requestUse command TIS_PC_ACC_RQUUSE
  to ACCESS Register in the time of default TIS_TIMEOUT_A.

  @param[in] TisReg                Pointer to TIS register.

  @retval    EFI_SUCCESS           Get the control of TPM chip.
  @retval    EFI_INVALID_PARAMETER TisReg is NULL.
  @retval    EFI_NOT_FOUND         TPM chip doesn't exit.
  @retval    EFI_TIMEOUT           Can't get the TPM control in time.
**/
EFI_STATUS
TisPcRequestUseTpm (
  IN      TIS_PC_REGISTERS_PTR  TisReg
  )
{
  EFI_STATUS  Status;

  if (TisReg == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!TisPcPresenceCheck (TisReg)) {
    return EFI_NOT_FOUND;
  }

  MmioWrite8 ((UINTN)&TisReg->Access, TIS_PC_ACC_RQUUSE);
  Status = TisPcWaitRegisterBits (
             &TisReg->Access,
             (UINT8)(TIS_PC_ACC_ACTIVE |TIS_PC_VALID),
             0,
             TIS_TIMEOUT_A
             );
  return Status;
  // if (EFI_ERROR (Status)) {
  //   return EFI_DEVICE_ERROR;
  // }

//   UINT8 GET_VERSION[] = { 0x10, 0x84, 0x00, 0x00 };
//   UINT8 *Out = NULL;
//   UINT32 OutSize = 0;
//   VOID *Cmd = NULL;
//   UINT32 CmdSize = 0;
//   UINT8 *Data8 = NULL;
//   UINT16 *Data16 = NULL;
//   UINT32 *Data32 = NULL;
//   UINT16 BurstCount;
//   UINT32 Index;
//   // UINT32 TpmOutSize;
//
//   Status = TisPcPrepareCommand (TisReg);
//   if (EFI_ERROR (Status)) {
//     DEBUG ((DEBUG_ERROR, "Tpm2 is not ready for command!\n"));
//     return EFI_DEVICE_ERROR;
//   }
//
//   CmdSize = sizeof (UINT16) + 2 * sizeof (UINT32) + sizeof (UINT16) + sizeof (UINT32) + sizeof (GET_VERSION);
//   Cmd = AllocateZeroPool (CmdSize);
//   Data16 = (UINT16 *)Cmd;
//   *Data16 = SwapBytes16 (0x8101);
//   Data32 = (UINT32 *)((UINT8 *)Cmd + sizeof (UINT16));
//   *Data32 = SwapBytes32(CmdSize);
//   Data8 = (UINT8 *)((UINT8 *)Cmd + 2 * sizeof (UINT16) + 3 * sizeof (UINT32));
//   CopyMem (Data8, GET_VERSION, sizeof (GET_VERSION));
//
//   DEBUG ((DEBUG_INFO, "\n\n\n\n"));
//   DEBUG ((DEBUG_INFO, "CmdSize - %04X\n", CmdSize));
//   for (UINTN i = 0 ; i < CmdSize ; i++)
//     DEBUG ((DEBUG_INFO, "%02X ", ((UINT8 *)Cmd)[i]));
//   DEBUG ((DEBUG_INFO, "\n\n\n\n"));
//
//   //
//   // Send the command data to Tpm
//   //
//   Index = 0;
//   while (Index < CmdSize) {
//     Status = TisPcReadBurstCount (TisReg, &BurstCount);
//     if (EFI_ERROR (Status)) {
//       Status = EFI_DEVICE_ERROR;
//       goto Exit;
//     }
//
//     for ( ; BurstCount > 0 && Index < CmdSize; BurstCount--) {
//       MmioWrite8 ((UINTN)&TisReg->DataFifo, *((UINT8 *)Cmd + Index));
//       Index++;
//     }
//   }
//
//   //
//   // Check the Tpm status STS_EXPECT change from 1 to 0
//   //
//   Status = TisPcWaitRegisterBits (
//              &TisReg->Status,
//              (UINT8)TIS_PC_VALID,
//              TIS_PC_STS_EXPECT,
//              TIS_TIMEOUT_C
//              );
//   if (EFI_ERROR (Status)) {
//     DEBUG ((DEBUG_ERROR, "Tpm2 The send buffer too small!\n"));
//     Status = EFI_BUFFER_TOO_SMALL;
//     goto Exit;
//   }
//
//   //
//   // Executed the TPM command and waiting for the response data ready
//   //
//   MmioWrite8 ((UINTN)&TisReg->Status, TIS_PC_STS_GO);
//
//
//
//   //
//   // RECEVING
//   //
//   //
//   // NOTE: That may take many seconds to minutes for certain commands, such as key generation.
//   //
//   Status = TisPcWaitRegisterBits (
//              &TisReg->Status,
//              (UINT8)(TIS_PC_VALID | TIS_PC_STS_DATA),
//              0,
//              TIS_TIMEOUT_MAX
//              );
//   if (EFI_ERROR (Status)) {
//     //
//     // dataAvail check timeout. Cancel the currently executing command by writing commandCancel,
//     // Expect TPM_RC_CANCELLED or successfully completed response.
//     //
//     DEBUG ((DEBUG_ERROR, "Wait for Tpm2 response data time out. Trying to cancel the command!!\n"));
//
//     MmioWrite32 ((UINTN)&TisReg->Status, TIS_PC_STS_CANCEL);
//     Status = TisPcWaitRegisterBits (
//                &TisReg->Status,
//                (UINT8)(TIS_PC_VALID | TIS_PC_STS_DATA),
//                0,
//                TIS_TIMEOUT_B
//                );
//     //
//     // Do not clear CANCEL bit here because Writes of 0 to this bit are ignored
//     //
//     if (EFI_ERROR (Status)) {
//       //
//       // Cancel executing command fail to get any response
//       // Try to abort the command with write of a 1 to commandReady in Command Execution state
//       //
//       Status = EFI_DEVICE_ERROR;
//       goto Exit;
//     }
//   }
//
//   //
//   // Get response data header
//   //
//   Index      = 0;
//   BurstCount = 0;
//   while (Index < sizeof (TPM2_SPDM_HEADER)) {
//     Status = TisPcReadBurstCount (TisReg, &BurstCount);
//     if (EFI_ERROR (Status)) {
//       Status = EFI_DEVICE_ERROR;
//       goto Exit;
//     }
//
//     for ( ; BurstCount > 0; BurstCount--) {
//       *(Out + Index) = MmioRead8 ((UINTN)&TisReg->DataFifo);
//       Index++;
//       if (Index == sizeof (TPM2_SPDM_HEADER)) {
//         break;
//       }
//     }
//   }
//
//   //
//   // Check the response data header (tag,parasize and returncode )
//   //
//   CopyMem (Data16, Out, sizeof (UINT16));
//   // TPM2 should not use this RSP_COMMAND
//   if (SwapBytes16 (*Data16) == TPM_ST_RSP_COMMAND) {
//     DEBUG ((DEBUG_ERROR, "TPM2: TPM_ST_RSP error - %x\n", TPM_ST_RSP_COMMAND));
//     Status = EFI_UNSUPPORTED;
//     goto Exit;
//   }
//
//   CopyMem (&OutSize, (Out + sizeof (UINT16)), sizeof (UINT32));
//   OutSize = SwapBytes32 (OutSize);
//   DEBUG ((DEBUG_INFO, "[EDKII] OutSize = 0x%08X\n", OutSize));
//   // if (*OutSize < TpmOutSize) {
//   //   Status = EFI_BUFFER_TOO_SMALL;
//   //   goto Exit;
//   // }
//
//   //
//   // Continue reading the remaining data
//   //
//   Index = sizeof (TPM2_SPDM_HEADER);
//   while ( Index < OutSize ) {
//     for ( ; BurstCount > 0; BurstCount--) {
//       *(Out + Index) = MmioRead8 ((UINTN)&TisReg->DataFifo);
//       Index++;
//       if (Index == OutSize) {
//         Status = EFI_SUCCESS;
//         goto Exit;
//       }
//     }
//
//     Status = TisPcReadBurstCount (TisReg, &BurstCount);
//     if (EFI_ERROR (Status)) {
//       Status = EFI_DEVICE_ERROR;
//       goto Exit;
//     }
//   }
//
// Exit:
//   MmioWrite8 ((UINTN)&TisReg->Status, TIS_PC_STS_READY);
//
//   DEBUG ((DEBUG_INFO, "Tpm2TisTpmCommand:\n\t"));
//   for (Index = 0; Index < OutSize; Index++) {
//     if ((Index != 0) && (Index % 16 == 0)) DEBUG ((DEBUG_INFO, "\n\t"));
//     DEBUG ((DEBUG_INFO, "%02x ", Out[Index]));
//   }
//   DEBUG ((DEBUG_INFO, "\n"));
  // return Status;
}

/**
  This service enables the sending of commands to the TPM2.

  @param[in]      InputParameterBlockSize  Size of the TPM2 input parameter block.
  @param[in]      InputParameterBlock      Pointer to the TPM2 input parameter block.
  @param[in,out]  OutputParameterBlockSize Size of the TPM2 output parameter block.
  @param[in]      OutputParameterBlock     Pointer to the TPM2 output parameter block.

  @retval EFI_SUCCESS            The command byte stream was successfully sent to the device and a response was successfully received.
  @retval EFI_DEVICE_ERROR       The command was not successfully sent to the device or a response was not successfully received from the device.
  @retval EFI_BUFFER_TOO_SMALL   The output parameter block is too small.
**/
EFI_STATUS
EFIAPI
DTpm2TisSubmitCommand (
  IN UINT32      InputParameterBlockSize,
  IN UINT8       *InputParameterBlock,
  IN OUT UINT32  *OutputParameterBlockSize,
  IN UINT8       *OutputParameterBlock
  )
{
  return Tpm2TisTpmCommand (
           (TIS_PC_REGISTERS_PTR)(UINTN)PcdGet64 (PcdTpmBaseAddress),
           InputParameterBlock,
           InputParameterBlockSize,
           OutputParameterBlock,
           OutputParameterBlockSize
           );
}

/**
  This service requests use TPM2.

  @retval EFI_SUCCESS      Get the control of TPM2 chip.
  @retval EFI_NOT_FOUND    TPM2 not found.
  @retval EFI_DEVICE_ERROR Unexpected device behavior.
**/
EFI_STATUS
EFIAPI
DTpm2TisRequestUseTpm (
  VOID
  )
{
  return TisPcRequestUseTpm ((TIS_PC_REGISTERS_PTR)(UINTN)PcdGet64 (PcdTpmBaseAddress));
}
