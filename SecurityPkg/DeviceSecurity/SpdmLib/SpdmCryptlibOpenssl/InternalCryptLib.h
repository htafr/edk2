/**
 *  Copyright Notice:
 *  Copyright 2021-2024 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * Internal include file for cryptlib.
 **/

#ifndef __INTERNAL_CRYPT_LIB_H__
#define __INTERNAL_CRYPT_LIB_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>

#include <hal/base.h>
#include <hal/library/memlib.h>
#include <hal/library/debuglib.h>
#include <hal/library/cryptlib.h>
#include <library/spdm_crypt_lib.h>

#include <CrtLibSupport.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x30200000L

#ifndef EVP_PKEY_PRIVATE_KEY
#define EVP_PKEY_PRIVATE_KEY EVP_PKEY_KEYPAIR
#endif

#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

#endif

#endif
