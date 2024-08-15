#ifndef _VIRTIO_BLK_SPDM_H
#define _VIRTIO_BLK_SPDM_H

#include "hal/base.h"
#include <Stub/SpdmLibStub.h>
#include <industry_standard/spdm.h>
#include <industry_standard/spdm_secured_message.h>
#include <IndustryStandard/Pci.h>
#include <IndustryStandard/Tpm20.h>
#include <IndustryStandard/UefiTcgPlatform.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiLib.h>
#include <Library/TpmMeasurementLib.h>
#include <Library/RngLib.h>
#include <Library/BaseCryptLib.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_transport_mctp_lib.h>

#define VIRTIO_BLK_T_SPDM     16
#define VIRTIO_BLK_T_SPDM_APP 32

#define LIBSPDM_TRANSPORT_HEADER_SIZE 64
#define LIBSPDM_TRANSPORT_TAIL_SIZE 64

/* define common LIBSPDM_TRANSPORT_ADDITIONAL_SIZE. It should be the biggest one. */
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE \
    (LIBSPDM_TRANSPORT_HEADER_SIZE + LIBSPDM_TRANSPORT_TAIL_SIZE)

#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE (0x1100 + \
                                    LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE (0x1200 + \
                                      LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_MAX_SPDM_MSG_SIZE
#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x1200
#endif

#define LIBSPDM_MAX_MESSAGE_BUFFER_SIZE 0x1200

typedef struct _SPDM_IO_PROTOCOL SPDM_IO_PROTOCOL;
typedef struct _SPDM_PROTOCOL SPDM_PROTOCOL;

#define SPDM_DRIVER_DEVICE_CONTEXT_SIGNATURE  SIGNATURE_32 ('S', 'D', 'D', 'C')
#define SPDM_DEVICE_INSTANCE_SIGNATURE  SIGNATURE_32 ('S', 'D', 'C', 'S')
#define SPDM_DEVICE_INSTANCE_FROM_LINK(a)  CR (a, SPDM_DEVICE_INSTANCE, Link, SPDM_DEVICE_INSTANCE_SIGNATURE)

typedef struct {
  UINTN                       Signature;
  EDKII_DEVICE_IDENTIFIER     DeviceId;
  EFI_DEVICE_PATH_PROTOCOL    *DevicePath;
  VOID                        *DeviceIo;
  SPDM_IO_PROTOCOL            *SpdmIoProtocol;
  // TBD
  SPDM_PROTOCOL               *SpdmProtocol;
  //
  // Status
  //
  BOOLEAN                     IsDeviceMeasured;
  BOOLEAN                     IsDeviceAuthenticated;
  UINT64                      DeviceUID;

  VOID                        *SpdmContext;
} SPDM_DRIVER_DEVICE_CONTEXT;

typedef struct {
  UINTN                         Signature;
  LIST_ENTRY                    Link;
  SPDM_DRIVER_DEVICE_CONTEXT    *SpdmDriverContext;
} SPDM_DEVICE_INSTANCE;

/**
  Set a SPDM local Data.

  @param  This                         Indicates a pointer to the calling context.
  @param  DataType                     Type of the session data.
  @param  Data                         A pointer to the session data.
  @param  DataSize                     Size of the session data.

  @retval RETURN_SUCCESS                  The SPDM session data is set successfully.
  @retval RETURN_INVALID_PARAMETER        The Data is NULL or the DataType is zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_ACCESS_DENIED            The DataType cannot be set.
  @retval RETURN_NOT_READY                Current session is not started.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_SET_DATA_FUNC)(
  IN     SPDM_PROTOCOL             *This,
  IN     SPDM_DATA_TYPE            DataType,
  IN     SPDM_DATA_PARAMETER       *Parameter,
  IN     VOID                      *Data,
  IN     UINTN                     DataSize
  );

/**
  Get a SPDM local or remote Data.

  If the data is session specific, the session ID should be input.

  @param  This                         Indicates a pointer to the calling context.
  @param  DataType                     Type of the session data.
  @param  Data                         A pointer to the session data.
  @param  DataSize                     Size of the session data. On input, it means the size of Data
                                       buffer. On output, it means the size of copied Data buffer if
                                       RETURN_SUCCESS, and means the size of desired Data buffer if
                                       RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS                  The SPDM session data is set successfully.
  @retval RETURN_INVALID_PARAMETER        The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_NOT_FOUND                The DataType cannot be found.
  @retval RETURN_NOT_READY                The DataType is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_DATA_FUNC)(
  IN     SPDM_PROTOCOL             *This,
  IN     SPDM_DATA_TYPE            DataType,
  IN     SPDM_DATA_PARAMETER       *Parameter,
  IN OUT VOID                      *Data,
  IN OUT UINTN                     *DataSize
  );

#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)
/**
  Start a SPDM Session.

  @param  This                         Indicates a pointer to the calling context.

  @retval RETURN_SUCCESS                  The SPDM session is started.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_START_SESSION_FUNC)(
  IN     SPDM_PROTOCOL        *This,
  IN     BOOLEAN              UsePsk,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
  OUT UINT32               *SessionId,
  OUT UINT8                *HeartbeatPeriod,
  OUT VOID                 *MeasurementHash
  );

/**
  Stop a SPDM Session.

  @param  This                         Indicates a pointer to the calling context.

  @retval RETURN_SUCCESS                  The SPDM session is stopped.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_STOP_SESSION_FUNC)(
  IN     SPDM_PROTOCOL        *This,
  IN     UINT32               SessionId,
  IN     UINT8                EndSessionAttributes
  );
#endif

/*
  Call GetVersion, GetCapabilities, NegotiateAlgorithms

  The negotiated data can be get via GetData.
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_INIT_CONNECTION_FUNC)(
  IN     SPDM_PROTOCOL        *This
  );

/*
  Get all digest of the CertificateChains returned from device.

  TotalDigestSize = sizeof(Digest) * Count in SlotMask
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_DIGEST_FUNC)(
  IN     SPDM_PROTOCOL        *This,
  OUT UINT8                *SlotMask,
  OUT VOID                 *TotalDigestBuffer
  );

/*
  Get CertificateChain in one slot returned from device.
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_CERTIFICATE_FUNC)(
  IN     SPDM_PROTOCOL        *This,
  IN     UINT8                SlotNum,
  IN OUT UINTN                *CertChainSize,
  OUT VOID                 *CertChain
  );

/*
  Authenticate based upon the key in one slot.
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_CHALLENGE_FUNC)(
  IN     SPDM_PROTOCOL        *This,
  IN     UINT8                SlotNum,
  IN     UINT8                MeasurementHashType,
  OUT VOID                 *MeasurementHash
  );

/*
  Get measurement
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_MEASUREMENT_FUNC)(
  IN     SPDM_PROTOCOL        *This,
  IN     UINT8                RequestAttribute,
  IN     UINT8                MeasurementOperation,
  IN     UINT8                SlotNum,
  OUT UINT8                *NumberOfBlocks,
  IN OUT UINT32               *MeasurementRecordLength,
  OUT VOID                 *MeasurementRecord
  );

/*
  Send receive SPDM data.
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_SEND_RECEIVE_DATA_FUNC)(
  IN     SPDM_PROTOCOL        *This,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
  IN OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  );

/**
  Send a SPDM transport layer message to a device.

  For requester, the message is an SPDM request.
  For responder, the message is an SPDM response.

  @param  This                         Indicates a pointer to the calling context.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than Timeout.

  @retval RETURN_SUCCESS               The SPDM message is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is sent to the device.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
typedef
SPDM_RETURN
(*SPDM_IO_SECURE_SEND_MESSAGE_FUNC) (
  IN     SPDM_IO_PROTOCOL  *This,
  IN     UINTN             MessageSize,
  IN CONST VOID            *Message,
  IN     UINT64            Timeout
  );

/**
  Receive a SPDM transport layer message from a device.

  For requester, the message is an SPDM response.
  For responder, the message is an SPDM request.

  @param  This                         Indicates a pointer to the calling context.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than Timeout.

  @retval RETURN_SUCCESS               The SPDM message is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is received from the device.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL, MessageSize is NULL or
                                       the *MessageSize is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
typedef
SPDM_RETURN
(*SPDM_IO_SECURE_RECEIVE_MESSAGE_FUNC) (
  IN     SPDM_IO_PROTOCOL  *This,
  IN OUT UINTN             *MessageSize,
  OUT VOID                 **Message,
  IN     UINT64            Timeout
  );

struct _SPDM_IO_PROTOCOL {
  SPDM_IO_SECURE_SEND_MESSAGE_FUNC       SendMessage;
  SPDM_IO_SECURE_RECEIVE_MESSAGE_FUNC    ReceiveMessage;
};

struct _SPDM_PROTOCOL {
  SPDM_SET_DATA_FUNC             SetData;
  SPDM_GET_DATA_FUNC             GetData;
  SPDM_INIT_CONNECTION_FUNC      InitConnection;
  SPDM_GET_DIGEST_FUNC           GetDigest;
  SPDM_GET_CERTIFICATE_FUNC      GetCertificate;
  SPDM_CHALLENGE_FUNC            Challenge;
  SPDM_GET_MEASUREMENT_FUNC      GetMeasurement;
#if (LIBSPDM_ENABLE_CAPABILITY_KEY_EX_CAP) || (LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP)
  SPDM_START_SESSION_FUNC        StartSession;
  SPDM_STOP_SESSION_FUNC         StopSession;
#endif
  SPDM_SEND_RECEIVE_DATA_FUNC    SendReceiveData;
};

#endif
