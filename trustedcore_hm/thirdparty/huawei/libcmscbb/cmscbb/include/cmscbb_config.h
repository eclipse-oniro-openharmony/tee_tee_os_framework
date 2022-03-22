/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */

/*
 * File Name          : cmscbb_config.h
 * Brief              : Compile switch configuration
 * Author             : t00307193
 * Creation Date      : 2016/08/17 10:08:28
 *      Date time           Author        Description
 *      2016/08/17 10:08    t00307193     new
 */
#ifndef H_CMS_VRF_CBB_CMSCBB_CONFIG_H
#define H_CMS_VRF_CBB_CMSCBB_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef CMSCBB_FOR_EMBED
#define CMSCBB_FOR_EMBED 0
#endif

#ifndef CMSCBB_FOR_WIRELESS
#define CMSCBB_FOR_WIRELESS 0
#endif /* !CMSCBB_FOR_WIRELESS */

#ifndef CMSCBB_FOR_IWARE
#define CMSCBB_FOR_IWARE 0
#endif

#ifndef CMSCBB_FOR_UEFI
#define CMSCBB_FOR_UEFI 0
#endif

#if CMSCBB_FOR_EMBED
#ifndef CMSCBB_SUPPORT_FILE
#define CMSCBB_SUPPORT_FILE 0
#endif

#ifndef CMSCBB_ENABLE_LOG
#define CMSCBB_ENABLE_LOG   0
#endif

#ifndef CMSCBB_SUPPORT_PEM
#define CMSCBB_SUPPORT_PEM  0
#endif

#ifndef CMSCBB_SUPPORT_NO_SIGNED_ATTR
#define CMSCBB_SUPPORT_NO_SIGNED_ATTR   0
#endif

#ifndef CMSCBB_NEED_RELOCATE
#define CMSCBB_NEED_RELOCATE 1
#endif

#ifndef CMSCBB_RELOC_STRICT_CHECK
#define CMSCBB_RELOC_STRICT_CHECK 1
#endif

#endif

#if CMSCBB_FOR_WIRELESS
#ifndef CMSCBB_ALLOW_NO_CHECK_TSA_CRL
#define CMSCBB_ALLOW_NO_CHECK_TSA_CRL 1
#endif
#endif

#if CMSCBB_FOR_IWARE

#ifndef CMSCBB_SUPPORT_FILE
#define CMSCBB_SUPPORT_FILE 0
#endif

#ifndef CMSCBB_SUPPORT_NO_SIGNED_ATTR
#define CMSCBB_SUPPORT_NO_SIGNED_ATTR   0
#endif

#ifndef CMSCBB_SUPPORT_PEM
#define CMSCBB_SUPPORT_PEM  0
#endif

#ifndef CMSCBB_CACHE_ASN_DATA
#define CMSCBB_CACHE_ASN_DATA 0
#endif /* !CMSCBB_CACHE_ASN_DATA */

#ifndef CMSCBB_SUPPORT_DIGEST_STREAM_MODE
#define CMSCBB_SUPPORT_DIGEST_STREAM_MODE 0
#endif

#ifndef CMSCBB_DELAY_ADDRESS_SET
#define CMSCBB_DELAY_ADDRESS_SET 1
#endif

#ifndef CMSCBB_WITHOUT_SECUREC
#define CMSCBB_WITHOUT_SECUREC 1
#endif
#endif

#if CMSCBB_FOR_UEFI
#ifndef CMSCBB_SUPPORT_FILE
#define CMSCBB_SUPPORT_FILE 0
#endif

#ifndef CMSCBB_SUPPORT_DIGEST_STREAM_MODE
#define CMSCBB_SUPPORT_DIGEST_STREAM_MODE 0
#endif

#ifndef CMSCBB_ALLOW_NO_CHECK_TSA_CRL
#define CMSCBB_ALLOW_NO_CHECK_TSA_CRL 1
#endif

#ifndef CMSCBB_X509_ATTR_COUNT
#define CMSCBB_X509_ATTR_COUNT 5
#endif

#ifndef CMSCBB_X509_ATTR_ENTRY_COUNT
#define CMSCBB_X509_ATTR_ENTRY_COUNT 5
#endif
#endif

/*
 * default settings
 */
#ifndef CMSCBB_VERSION
#define CMSCBB_VERSION "V100R002C00SPC650"
#endif

#ifndef CMSCBB_WITHOUT_SECUREC
#define CMSCBB_WITHOUT_SECUREC 0
#endif

/* File Interface switch */
#ifndef CMSCBB_SUPPORT_FILE
#define CMSCBB_SUPPORT_FILE 1
#endif

/* Log function switch, recommended to enable */
#ifndef CMSCBB_ENABLE_LOG
#define CMSCBB_ENABLE_LOG 1
#endif /* !CMSCBB_ENABLE_LOG */

/* Log level settings,1: ERROR, 2: WARNING, 3: DEBUG, 4: INFO */
#ifndef CMSCBB_LOG_LEVEL
#define CMSCBB_LOG_LEVEL 1  /* choice 1~4 */
#endif

/* PEM Format (Base64 encoded string) support switch */
#ifndef CMSCBB_SUPPORT_PEM
#define CMSCBB_SUPPORT_PEM 1
#endif

/* Signature property switch is supported and cannot be closed */
#ifndef CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
#define CMSCBB_SUPPORT_SIGNED_ATTRIBUTE 1
#endif

/* Unsupported unsigned property switch */
#ifndef CMSCBB_SUPPORT_NO_SIGNED_ATTR
#define CMSCBB_SUPPORT_NO_SIGNED_ATTR 1
#endif

#if (!CMSCBB_SUPPORT_SIGNED_ATTRIBUTE && !CMSCBB_SUPPORT_NO_SIGNED_ATTR)
#error Macro CMSCBB_SUPPORT_SIGNED_ATTRIBUTE and CMSCBB_SUPPORT_NO_SIGNED_ATTR should not both 0
#endif

/* CRL comparison function switch */
#ifndef CMSCBB_SUPPORT_CRL_COMPARE
#define CMSCBB_SUPPORT_CRL_COMPARE 1
#endif

/* Indirect CRL Support switch, cannot close */
#ifndef CMSCBB_SUPPORT_INDIRECT_CRL
#define CMSCBB_SUPPORT_INDIRECT_CRL 1
#endif /* !CMSCBB_SUPPORT_INDIRECT_CRL */

/* SHA384 support switch, recommended to enable */
#ifndef CMSCBB_SUPPORT_SHA384
#define CMSCBB_SUPPORT_SHA384 1
#endif

/* SHA512 support switch, recommended to enable */
#ifndef CMSCBB_SUPPORT_SHA512
#define CMSCBB_SUPPORT_SHA512 1
#endif

/* Piecewise (streaming) calculations that support hashing */
#ifndef CMSCBB_SUPPORT_DIGEST_STREAM_MODE
#define CMSCBB_SUPPORT_DIGEST_STREAM_MODE 1
#endif

/* Support for runtime settings template callback */
#ifndef CMSCBB_DELAY_ADDRESS_SET
#define CMSCBB_DELAY_ADDRESS_SET 0
#endif

/*
 * Cache signatures, certificates, and CRL switches, such as non-memory usage size limits, are not recommended for shutdown.
 * The following conditions are met to consider shutting down:
 * 1. Full use of the DER format for signatures, certificates and CRL data (not files);
 * 2. And the data is not released from memory until the verification is complete.
 */
#ifndef CMSCBB_CACHE_ASN_DATA
#define CMSCBB_CACHE_ASN_DATA 1
#endif /* !CMSCBB_CACHE_ASN_DATA */

/*
 * Address redirection switch.
 * The values of static variables for pointer types in some embedded environments are determined at compile time.
 * However, only the offset of the relative 0 addresses of these pointers is recorded at compile time.
 * The runtime program loaded the base site is not starting from 0,
 * In this case, you need to turn on the address redirection feature, And when creating a context, you need to pass in a real program-loading base address.
 */
#ifndef CMSCBB_NEED_RELOCATE
#define CMSCBB_NEED_RELOCATE 0
#endif

/*
 * This option increases the volume of the compilation by determining whether the static pointer has been redirected through the strict checksum mode
 * If you confirm that the memory base address is not less than the pointer offset address you can not enable
 */
#ifndef CMSCBB_RELOC_STRICT_CHECK
#define CMSCBB_RELOC_STRICT_CHECK 0
#endif

#if (!CMSCBB_NEED_RELOCATE && CMSCBB_RELOC_STRICT_CHECK)
#error Macro CMSCBB_RELOC_STRICT_CHECK can not be 1 when CMSCBB_NEED_RELOCATE is 0
#endif

/* Do not check CRL switch when verifying, disable */
#ifndef CMSCBB_ENABLE_VERIFY_WITHOUT_CRL
#define CMSCBB_ENABLE_VERIFY_WITHOUT_CRL 0
#endif

/* The CRL switch issued by the timestamp CA is not checked at validation time. */
#ifndef CMSCBB_ALLOW_NO_CHECK_TSA_CRL
#define CMSCBB_ALLOW_NO_CHECK_TSA_CRL 0
#endif

/* Enable the structure body byte alignment mode */
#ifndef CMSCBB_BYTE_ALIGN
#define CMSCBB_BYTE_ALIGN 1
#endif /* !CMSCBB_BYTE_ALIGN */

/* Code that is streamlined */
#ifndef CMSCBB_MAX_MODE
#define CMSCBB_MAX_MODE 0
#endif

/* Strictly check the mode switch, these checks are irrelevant to the verification process */
#ifndef CMSCBB_STRICT_CHECK
#define CMSCBB_STRICT_CHECK 0
#endif

/* Strict PKI implementation mode switch, because this CBB only for the company issued the signature and certificate, streamlined the partial use of PKI characteristics */
#ifndef CMSCBB_STRICT_MODE
#define CMSCBB_STRICT_MODE 0
#endif

/* Support the number of certificate properties, for the future extensibility, reserved a certain upgrade space, Products can be modified according to their own conditions to reduce memory footprint, recommended not less than 5 */
#ifndef CMSCBB_X509_ATTR_COUNT
#define CMSCBB_X509_ATTR_COUNT 10
#endif

/* Support the number of certificate properties, for the future extensibility, reserved a certain upgrade space, Products can be modified according to their own conditions to reduce memory footprint, recommended not less than 5 */
#ifndef CMSCBB_X509_ATTR_ENTRY_COUNT
#define CMSCBB_X509_ATTR_ENTRY_COUNT 10
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* H_CMS_VRF_CBB_CMSCBB_CONFIG_H */
