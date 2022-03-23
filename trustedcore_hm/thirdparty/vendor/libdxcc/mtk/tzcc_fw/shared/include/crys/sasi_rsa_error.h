/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef SaSi_RSA_ERROR_H
#define SaSi_RSA_ERROR_H

#include "sasi_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ! @file
 *  @brief This module contains the definitions of the SaSi RSA errors.
 */

/* *********************** Defines **************************** */

/* PKI RSA module on the SaSi layer base address - 0x00F00400 */

/* The SaSi RSA module errors */
#define SaSi_RSA_INVALID_MODULUS_SIZE                     (SaSi_RSA_MODULE_ERROR_BASE + 0x0UL)
#define SaSi_RSA_INVALID_MODULUS_POINTER_ERROR            (SaSi_RSA_MODULE_ERROR_BASE + 0x1UL)
#define SaSi_RSA_INVALID_EXPONENT_POINTER_ERROR           (SaSi_RSA_MODULE_ERROR_BASE + 0x2UL)
#define SaSi_RSA_INVALID_PUB_KEY_STRUCT_POINTER_ERROR     (SaSi_RSA_MODULE_ERROR_BASE + 0x3UL)
#define SaSi_RSA_INVALID_PRIV_KEY_STRUCT_POINTER_ERROR    (SaSi_RSA_MODULE_ERROR_BASE + 0x4UL)
#define SaSi_RSA_INVALID_EXPONENT_VAL                     (SaSi_RSA_MODULE_ERROR_BASE + 0x5UL)
#define SaSi_RSA_INVALID_EXPONENT_SIZE                    (SaSi_RSA_MODULE_ERROR_BASE + 0x6UL)
#define SaSi_RSA_INVALID_CRT_FIRST_FACTOR_POINTER_ERROR   (SaSi_RSA_MODULE_ERROR_BASE + 0x7UL)
#define SaSi_RSA_INVALID_CRT_SECOND_FACTOR_POINTER_ERROR  (SaSi_RSA_MODULE_ERROR_BASE + 0x8UL)
#define SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXP_PTR_ERROR   (SaSi_RSA_MODULE_ERROR_BASE + 0x9UL)
#define SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXP_PTR_ERROR  (SaSi_RSA_MODULE_ERROR_BASE + 0xAUL)
#define SaSi_RSA_INVALID_CRT_COEFFICIENT_PTR_ERROR        (SaSi_RSA_MODULE_ERROR_BASE + 0xBUL)
#define SaSi_RSA_INVALID_CRT_FIRST_FACTOR_SIZE            (SaSi_RSA_MODULE_ERROR_BASE + 0xCUL)
#define SaSi_RSA_INVALID_CRT_SECOND_FACTOR_SIZE           (SaSi_RSA_MODULE_ERROR_BASE + 0xDUL)
#define SaSi_RSA_INVALID_CRT_FIRST_AND_SECOND_FACTOR_SIZE (SaSi_RSA_MODULE_ERROR_BASE + 0xEUL)
#define SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXPONENT_VAL    (SaSi_RSA_MODULE_ERROR_BASE + 0xFUL)
#define SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXPONENT_VAL   (SaSi_RSA_MODULE_ERROR_BASE + 0x10UL)
#define SaSi_RSA_INVALID_CRT_COEFF_VAL                    (SaSi_RSA_MODULE_ERROR_BASE + 0x11UL)
#define SaSi_RSA_DATA_POINTER_INVALID_ERROR               (SaSi_RSA_MODULE_ERROR_BASE + 0x12UL)
#define SaSi_RSA_INVALID_MESSAGE_DATA_SIZE                (SaSi_RSA_MODULE_ERROR_BASE + 0x13UL)
#define SaSi_RSA_INVALID_MESSAGE_VAL                      (SaSi_RSA_MODULE_ERROR_BASE + 0x14UL)

#define SaSi_RSA_MODULUS_EVEN_ERROR                 (SaSi_RSA_MODULE_ERROR_BASE + 0x15UL)
#define SaSi_RSA_INVALID_USER_CONTEXT_POINTER_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x16UL)
#define SaSi_RSA_HASH_ILLEGAL_OPERATION_MODE_ERROR  (SaSi_RSA_MODULE_ERROR_BASE + 0x17UL)
#define SaSi_RSA_MGF_ILLEGAL_ARG_ERROR              (SaSi_RSA_MODULE_ERROR_BASE + 0x18UL)
#define SaSi_RSA_PKCS1_VER_ARG_ERROR                (SaSi_RSA_MODULE_ERROR_BASE + 0x19UL)

#define SaSi_RSA_PRIV_KEY_VALIDATION_TAG_ERROR               (SaSi_RSA_MODULE_ERROR_BASE + 0x1AUL)
#define SaSi_RSA_PUB_KEY_VALIDATION_TAG_ERROR                (SaSi_RSA_MODULE_ERROR_BASE + 0x1BUL)
#define SaSi_RSA_USER_CONTEXT_VALIDATION_TAG_ERROR           (SaSi_RSA_MODULE_ERROR_BASE + 0x1CUL)
#define SaSi_RSA_INVALID_OUTPUT_POINTER_ERROR                (SaSi_RSA_MODULE_ERROR_BASE + 0x1DUL)
#define SaSi_RSA_INVALID_OUTPUT_SIZE_POINTER_ERROR           (SaSi_RSA_MODULE_ERROR_BASE + 0x1FUL)
#define SaSi_RSA_CONV_TO_CRT_INVALID_TEMP_BUFF_POINTER_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x20UL)

#define SaSi_RSA_BASE_OAEP_ENCODE_PARAMETER_STRING_TOO_LONG (SaSi_RSA_MODULE_ERROR_BASE + 0x22UL)
#define SaSi_RSA_BASE_OAEP_DECODE_PARAMETER_STRING_TOO_LONG (SaSi_RSA_MODULE_ERROR_BASE + 0x23UL)
#define SaSi_RSA_BASE_OAEP_ENCODE_MESSAGE_TOO_LONG          (SaSi_RSA_MODULE_ERROR_BASE + 0x24UL)
#define SaSi_RSA_BASE_OAEP_DECODE_MESSAGE_TOO_LONG          (SaSi_RSA_MODULE_ERROR_BASE + 0x25UL)
#define SaSi_RSA_KEY_GEN_DATA_STRUCT_POINTER_INVALID        (SaSi_RSA_MODULE_ERROR_BASE + 0x26UL)
#define SaSi_RSA_PRIM_DATA_STRUCT_POINTER_INVALID           (SaSi_RSA_MODULE_ERROR_BASE + 0x27UL)
#define SaSi_RSA_INVALID_MESSAGE_BUFFER_SIZE                (SaSi_RSA_MODULE_ERROR_BASE + 0x28UL)
#define SaSi_RSA_INVALID_SIGNATURE_BUFFER_SIZE              (SaSi_RSA_MODULE_ERROR_BASE + 0x29UL)
#define SaSi_RSA_INVALID_MOD_BUFFER_SIZE_POINTER            (SaSi_RSA_MODULE_ERROR_BASE + 0x2AUL)
#define SaSi_RSA_INVALID_EXP_BUFFER_SIZE_POINTER            (SaSi_RSA_MODULE_ERROR_BASE + 0x2BUL)
#define SaSi_RSA_INVALID_SIGNATURE_BUFFER_POINTER           (SaSi_RSA_MODULE_ERROR_BASE + 0x2CUL)
#define SaSi_RSA_WRONG_PRIVATE_KEY_TYPE                     (SaSi_RSA_MODULE_ERROR_BASE + 0x2DUL)

#define SaSi_RSA_INVALID_CRT_FIRST_FACTOR_SIZE_POINTER_ERROR  (SaSi_RSA_MODULE_ERROR_BASE + 0x2EUL)
#define SaSi_RSA_INVALID_CRT_SECOND_FACTOR_SIZE_POINTER_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x2FUL)
#define SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXP_SIZE_PTR_ERROR  (SaSi_RSA_MODULE_ERROR_BASE + 0x30UL)
#define SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXP_SIZE_PTR_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x31UL)
#define SaSi_RSA_INVALID_CRT_COEFFICIENT_SIZE_PTR_ERROR       (SaSi_RSA_MODULE_ERROR_BASE + 0x32UL)

#define SaSi_RSA_INVALID_CRT_FIRST_FACTOR_SIZE_ERROR      (SaSi_RSA_MODULE_ERROR_BASE + 0x33UL)
#define SaSi_RSA_INVALID_CRT_SECOND_FACTOR_SIZE_ERROR     (SaSi_RSA_MODULE_ERROR_BASE + 0x34UL)
#define SaSi_RSA_INVALID_CRT_FIRST_FACTOR_EXP_SIZE_ERROR  (SaSi_RSA_MODULE_ERROR_BASE + 0x35UL)
#define SaSi_RSA_INVALID_CRT_SECOND_FACTOR_EXP_SIZE_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x36UL)
#define SaSi_RSA_INVALID_CRT_COEFFICIENT_SIZE_ERROR       (SaSi_RSA_MODULE_ERROR_BASE + 0x37UL)
#define SaSi_RSA_KEY_GEN_CONDITIONAL_TEST_FAIL_ERROR      (SaSi_RSA_MODULE_ERROR_BASE + 0x38UL)

#define SaSi_RSA_CAN_NOT_GENERATE_RAND_IN_RANGE  (SaSi_RSA_MODULE_ERROR_BASE + 0x39UL)
#define SaSi_RSA_INVALID_CRT_PARAMETR_SIZE_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x3AUL)

#define SaSi_RSA_INVALID_MODULUS_ERROR         (SaSi_RSA_MODULE_ERROR_BASE + 0x40UL)
#define SaSi_RSA_INVALID_PTR_ERROR             (SaSi_RSA_MODULE_ERROR_BASE + 0x41UL)
#define SaSi_RSA_INVALID_DECRYPRION_MODE_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x42UL)

#define SaSi_RSA_GENERATED_PRIV_KEY_IS_TOO_LOW (SaSi_RSA_MODULE_ERROR_BASE + 0x43UL)
#define SaSi_RSA_KEY_GENERATION_FAILURE_ERROR  (SaSi_RSA_MODULE_ERROR_BASE + 0x44UL)

/* ***************************************************************************************
 * PKCS#1 VERSION 1.5 ERRORS
 * ************************************************************************************* */
#define SaSi_RSA_BER_ENCODING_OK                           SaSi_OK
#define SaSi_RSA_ERROR_BER_PARSING                         (SaSi_RSA_MODULE_ERROR_BASE + 0x51UL)
#define SaSi_RSA_ENCODE_15_MSG_OUT_OF_RANGE                (SaSi_RSA_MODULE_ERROR_BASE + 0x52UL)
#define SaSi_RSA_ENCODE_15_PS_TOO_SHORT                    (SaSi_RSA_MODULE_ERROR_BASE + 0x53UL)
#define SaSi_RSA_PKCS1_15_BLOCK_TYPE_NOT_SUPPORTED         (SaSi_RSA_MODULE_ERROR_BASE + 0x54UL)
#define SaSi_RSA_15_ERROR_IN_DECRYPTED_BLOCK_PARSING       (SaSi_RSA_MODULE_ERROR_BASE + 0x55UL)
#define SaSi_RSA_ERROR_IN_RANDOM_OPERATION_FOR_ENCODE      (SaSi_RSA_MODULE_ERROR_BASE + 0x56UL)
#define SaSi_RSA_ERROR_VER15_INCONSISTENT_VERIFY           (SaSi_RSA_MODULE_ERROR_BASE + 0x57UL)
#define SaSi_RSA_INVALID_MESSAGE_DATA_SIZE_IN_NO_HASH_CASE (SaSi_RSA_MODULE_ERROR_BASE + 0x58UL)
#define SaSi_RSA_INVALID_MESSAGE_DATA_SIZE_IN_SSL_CASE     (SaSi_RSA_MODULE_ERROR_BASE + 0x59UL)
#define SaSi_RSA_PKCS15_VERIFY_BER_ENCODING_HASH_TYPE \
    (SaSi_RSA_MODULE_ERROR_BASE +                     \
     0x60UL) /* !< \internal PKCS#1 Ver 1.5 verify hash input inconsistent with hash mode derived from signature */
#define SaSi_RSA_GET_DER_HASH_MODE_ILLEGAL (SaSi_RSA_MODULE_ERROR_BASE + 0x61UL)

/* ***************************************************************************************
 * PKCS#1 VERSION 2.1 ERRORS
 * ************************************************************************************* */
#define SaSi_RSA_PSS_ENCODING_MODULUS_HASH_SALT_LENGTHS_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x80UL)
#define SaSi_RSA_BASE_MGF_MASK_TOO_LONG                       (SaSi_RSA_MODULE_ERROR_BASE + 0x81UL)
#define SaSi_RSA_ERROR_PSS_INCONSISTENT_VERIFY                (SaSi_RSA_MODULE_ERROR_BASE + 0x82UL)
#define SaSi_RSA_OAEP_VER21_MESSAGE_TOO_LONG                  (SaSi_RSA_MODULE_ERROR_BASE + 0x83UL)
#define SaSi_RSA_ERROR_IN_DECRYPTED_BLOCK_PARSING             (SaSi_RSA_MODULE_ERROR_BASE + 0x84UL)
#define SaSi_RSA_OAEP_DECODE_ERROR                            (SaSi_RSA_MODULE_ERROR_BASE + 0x85UL)
#define SaSi_RSA_15_ERROR_IN_DECRYPTED_DATA_SIZE              (SaSi_RSA_MODULE_ERROR_BASE + 0x86UL)
#define SaSi_RSA_15_ERROR_IN_DECRYPTED_DATA                   (SaSi_RSA_MODULE_ERROR_BASE + 0x87UL)
#define SaSi_RSA_OAEP_L_POINTER_ERROR                         (SaSi_RSA_MODULE_ERROR_BASE + 0x88UL)
#define SaSi_RSA_DECRYPT_INVALID_OUTPUT_SIZE                  (SaSi_RSA_MODULE_ERROR_BASE + 0x89UL)
#define SaSi_RSA_DECRYPT_OUTPUT_SIZE_POINTER_ERROR            (SaSi_RSA_MODULE_ERROR_BASE + 0x8AUL)

#define SaSi_RSA_HOST_MSG_GENERAL_RPC_A_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x90UL)
#define SaSi_RSA_HOST_MSG_GENERAL_RPC_B_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x91UL)
#define SaSi_RSA_HOST_MSG_GENERAL_RPC_C_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x92UL)

#define SaSi_RSA_ILLEGAL_PARAMS_ACCORDING_TO_PRIV_ERROR (SaSi_RSA_MODULE_ERROR_BASE + 0x93UL)
#define SaSi_RSA_IS_NOT_SUPPORTED                       (SaSi_RSA_MODULE_ERROR_BASE + 0xFFUL)

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/* *********************** Structs  **************************** */

/* *********************** Public Variables ******************** */

/* *********************** Public Functions ******************** */

#ifdef __cplusplus
}
#endif

#endif
