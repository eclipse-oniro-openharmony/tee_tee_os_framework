/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, drivers cmd id
 * Create: 2019-11-19
 */
#ifndef DRIVERS_SRE_SYSCALLS_ID_H
#define DRIVERS_SRE_SYSCALLS_ID_H

/*
 * Syscall Numbers for platdrv and timer driver
 *
 * 0x9800 - 0x980f are reserved for driver (MDRV_MODULE_ID in drv_call.h)
 * cannot use those cmd id when add new command
 */
/* Timer */
#define SW_SYSCALL_TIMER_BASE              0xf050
#define SW_SYSCALL_TIMER_CREATE            0xf051
#define SW_SYSCALL_TIMER_START             0xf052
#define SW_SYSCALL_TIMER_DESTORY           0xf053
#define SW_SYSCALL_TIMER_STOP              0xf054
#define SW_SYSCALL_TIMER_READSTAMP         0xf055
#define SW_SYSCALL_READ_TIMER_COUNT        0xf056
#define SW_SYSCALL_GET_TIMER_EXPIRE        0xf057
#define SW_SYSCALL_CHECK_TIMER             0xf058
#define SW_SYSCALL_GET_STARTUP_TIME        0xf05a
#define SW_SYSCALL_SET_TIMER_PERMISSION    0xf05b
#define SW_SYSCALL_INIT_TIMER_DRV          0xf05c
#define SW_SYSCALL_RELEASE_TIMER_EVENT     0xf05e
/* RTC */
#define SW_SYSCALL_GET_RTC_TIME            0xf05f
#define SW_SYSCALL_INIT_RTC_TIME           0xf060
#define SW_SYSCALL_ADJUST_SYS_TIME         0xf061
#define SW_SYSCALL_GET_SYS_DATE_TIME       0xf062
#define SW_SYSCALL_GEN_SYS_DATE_TIME       0xf063
#define SW_SYSCALL_GET_SYS_RTC_TIME_KERNEL 0xf064
#define SW_SYSCALL_GET_SYS_RTC_TIME_OFFSET 0xf065
#define SW_SYSCALL_TIMER_MAX               0xf066

#define SW_SYSCALL_HWI_IPCREGISTER         0xf0ea
#define SW_SYSCALL_HWI_IPCDEREGISTER       0xf0eb

/* sys */
#define SW_SYSCALL_SYS_OSTSKEXIT 0xf0f0

/* mod manage */
#define SW_SYSCALL_OPEN_MOD           0xf2e0
#define SW_SYSCALL_CLOSE_MOD          0xf2e1

/* dyion mem */
#define SW_SYSCALL_SET_DYNMEM_CONFIG       0xf1e0

/* cc */
#define SW_SYSCALL_CC_DX_CCLIBINIT                         0xc000
#define SW_SYSCALL_CC_CRYS_HASH_INIT                       0xc004
#define SW_SYSCALL_CC_CRYS_HASH_UPDATE                     0xc008
#define SW_SYSCALL_CC_CRYS_HASH_FINISH                     0xc00c
#define SW_SYSCALL_CC_CRYS_HASH_FREE                       0xc010
#define SW_SYSCALL_CC_CRYS_HASH                            0xc014
#define SW_SYSCALL_CC_CRYS_HMAC_INIT                       0xc018
#define SW_SYSCALL_CC_CRYS_HMAC_UPDATE                     0xc01c
#define SW_SYSCALL_CC_CRYS_HMAC_FINISH                     0xc020
#define SW_SYSCALL_CC_CRYS_HMAC_FREE                       0xc024
#define SW_SYSCALL_CC_CRYS_HMAC                            0xc028
#define SW_SYSCALL_CC_CRYS_DES_INIT                        0xc02c
#define SW_SYSCALL_CC_CRYS_DES_BLOCK                       0xc030
#define SW_SYSCALL_CC_CRYS_DES                             0xc034
#define SW_SYSCALL_CC_CRYS_AES                             0xc036
#define SW_SYSCALL_CC_CRYS_AES_INIT                        0xc038
#define SW_SYSCALL_CC_CRYS_AES_BLOCK                       0xc03c
#define SW_SYSCALL_CC_CRYS_AES_FINISH                      0xc040
#define SW_SYSCALL_CC_CRYS_AESCCM                          0xc044
#define SW_SYSCALL_CC_CRYS_AESCCM_INIT                     0xc048
#define SW_SYSCALL_CC_CRYS_AESCCM_BLOCKADATA               0xc04c
#define SW_SYSCALL_CC_CRYS_AESCCM_FINISH                   0xc050
#define SW_SYSCALL_CC_CRYS_KDF_KEYDERIVFUNC                0xc054
#define SW_SYSCALL_CC_DX_UTIL_CMACDERIVEKEY                0xc058
#define SW_SYSCALL_CC_CRYS_RND_INSTANTIATION               0xc05c
#define SW_SYSCALL_CC_CRYS_RND_UNINSTANTIATION             0xc060
#define SW_SYSCALL_CC_CRYS_RND_RESEEDING                   0xc064
#define SW_SYSCALL_CC_CRYS_RND_GENERATEVECTOR              0xc068
#define SW_SYSCALL_CC_CRYS_RND_GENERATEVECTOR_EPS          0xc069
#define SW_SYSCALL_CC_CRYS_RND_GENERATEVECTORINRANGE       0xc06c
#define SW_SYSCALL_CC_CRYS_RND_ADDADDITIONALINPUT          0xc070
#define SW_SYSCALL_CC_CRYS_RND_ENTERKATMODE                0xc074
#define SW_SYSCALL_CC_CRYS_RND_DISABLEKATMODE              0xc078
#define SW_SYSCALL_CC_CRYS_RSA_BUILD_PUBKEY                0xc07c
#define SW_SYSCALL_CC_CRYS_RSA_BUILD_PRIVKEY               0xc080
#define SW_SYSCALL_CC_CRYS_RSA_BUILD_PRIVKEYCRT            0xc084
#define SW_SYSCALL_CC_CRYS_RSA_BUILD_CONVERTPRIVKEYTOCRT   0xc088
#define SW_SYSCALL_CC_CRYS_RSA_GET_PUBKEY                  0xc08c
#define SW_SYSCALL_CC_CRYS_RSA_GET_MODSIZEFROMPUBKEY       0xc090
#define SW_SYSCALL_CC_CRYS_RSA_GET_PRIVKEYCRT              0xc098
#define SW_SYSCALL_CC_CRYS_RSA_GET_PRIVKEYMODULUS          0xc09c
#define SW_SYSCALL_CC__DX_RSA_SCHEMES_ENCRYPT              0xc0a0
#define SW_SYSCALL_CC__DX_RSA_SIGN                         0xc0a4
#define SW_SYSCALL_CC__DX_RSA_VERIFY                       0xc0a8
#define SW_SYSCALL_CC_CRYS_RSA_PRIM_ENCRYPT                0xc0ac
#define SW_SYSCALL_CC_CRYS_RSA_PRIM_DECRYPT                0xc0b0
#define SW_SYSCALL_CC_CRYS_DES_FREE                        0xc0b4
#define SW_SYSCALL_CC_CRYS_RSA_KG_GENERATEKEYPAIRCRT       0xc0b8
#define SW_SYSCALL_CC_CRYS_RSA_KG_GENERATEKEYPAIR          0xc0bc
#define SW_SYSCALL_CC__DX_RSA_SCHEMES_DECRYPT              0xc0c0
#define SW_SYSCALL_CC_CRYS_DH_PKCS3_GENERATE_PUBPRV        0xc0c4
#define SW_SYSCALL_CC_CRYS_DH_ANSI_X942_GENERATE_PUBPRV    0xc0c8
#define SW_SYSCALL_CC_CRYS_DH_GET_SECRETKEY                0xc0cc
#define SW_SYSCALL_CC_CRYS_DH_X942_GETSECRET_DATA          0xc0d0
#define SW_SYSCALL_CC_CRYS_DH_X942_HYBRIDGET_SECRETDATA    0xc0d4
#define SW_SYSCALL_CC_CRYS_AES_SETIV                       0xc0d8
#define SW_SYSCALL_CC_CRYS_AESCCM_BLOCK_TEXTDATA           0xc0dc
#define SW_SYSCALL_DX_UTIL_OEMASSETUNPACK                  0xc0e0
#define SW_SYSCALL_GET_PROVISION_KEY                       0xc0e4
#define SW_SYSCALL_WRITE_TO_HDMI_SRAM                      0xc0e8
#define SW_SYSCALL_CC_SECS_POWER_ON                   0xc0ec
#define SW_SYSCALL_CC_SECS_POWER_DOWN                 0xc0f0

/* ecc */
#define SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PUBLKEY             0xc0f3
#define SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PUBLKEY_PARTLYCHECK 0xc0f4
#define SW_SYSCALL_CC_CRYS_ECPKI_BUILDPUBLKEY_FULLCHECK    0xc0f5
#define SW_SYSCALL_CC_CRYS_ECPKI_BUILD_PRIVKEY             0xc0f6
#define SW_SYSCALL_CC_CRYS_ECPKI_EXPORTPUBLKEY             0xc0f7
#define SW_SYSCALL_CC_CRYS_ECDH_SVDP_DH                    0xc0f8
#define SW_SYSCALL_CC_CRYS_ECDSA_SIGN                      0xc0f9
#define SW_SYSCALL_CC_CRYS_ECDSA_VERIFY                    0xc0fa
#define SW_SYSCALL_CC_CRYS_ECPKI_ELGAMAL_ENCRYPT           0xc0fb
#define SW_SYSCALL_CC_CRYS_ECPKI_ELGAMAL_DECRYPT           0xc0fc
#define SW_SYSCALL_CC_CRYS_ECPKI_GENKEY_PAIR               0xc0fd
#define SW_SYSCALL_CC_CRYS_ECDSA_SIGN_INIT                 0xc0fe
#define SW_SYSCALL_CC_CRYS_ECDSA_SIGN_UPDATE               0xc0ff
#define SW_SYSCALL_CC_CRYS_ECDSA_SIGN_FINISH               0xc100
#define SW_SYSCALL_CC_CRYS_ECDSA_VERIFY_INIT               0xc101
#define SW_SYSCALL_CC_CRYS_ECDSA_VERIFY_UPDATE             0xc102
#define SW_SYSCALL_CC_CRYS_ECDSA_VERIFY_FINISH             0xc103

/* sec boot */
#define SW_GET_CUID                                        0xe002
#define SW_COPY_SOC_DATA_TYPE                              0xe003
#define SW_VERIFY_SOC_DATA_TYPE                            0xe004
#define SW_SOC_IMAGE_RESET                                 0xe005
#define SW_SOC_IMAGE_SET                                   0xe006
#define SW_SOC_GET_VRL_ADDR                                0xe007
#define SW_PROCESS_SOC_ADDR                                0xe008

/* anti root */
#define SW_SYSCALL_ROOT_READ                               0xe401
#define SW_SYSCALL_ROOT_WRITE                              0xe402

/* root check */
#define SW_SYSCALL_IS_DEVICE_ROOTED                        0xe400

#define SW_SYSCALL_GET_TEESHAREDMEM                        0xe611
#define SW_SYSCALL_GET_TLV_TEESHAREDMEM                    0xe612

#define SW_SYSCALL_EXIST_SE                              0xc300
#define SW_SYSCALL_SE_CRYPTO                             0xc301

/* EPS */
#define SW_SYSCALL_EPS_SUPPORTCDRMENHANCE       0xc400
#define SW_SYSCALL_CC_EPS_CTRL                  0xc401
#define SW_SYSCALL_CC_EPS_SM2_SIGN              0xc402
#define SW_SYSCALL_CC_EPS_SM2_VERIFY            0xc403
#define SW_SYSCALL_CC_EPS_SM2_ENCRYPT           0xc404
#define SW_SYSCALL_CC_EPS_SM2_DECRYPT           0xc405
#define SW_SYSCALL_CC_EPS_SM4_SYMMETRIC_ENCRYPT 0xc406
#define SW_SYSCALL_CC_EPS_SM4_SYMMETRIC_DECRYPT 0xc407
#define SW_SYSCALL_CC_EPS_SM4_CONFIG            0xc408
#define SW_SYSCALL_CC_EPS_SM4_CENC_DECRYPT      0xc409

#define SW_SYSCALL_SE_CHANNELINFO_READ          0xc500
#define SW_SYSCALL_SE_CHANNELINFO_WRITE         0xc501
#define SW_SYSCALL_SE_DEACTIVE_WRITE            0xc502
#define SW_SYSCALL_SE_DEACTIVE_READ             0xc503
#define SW_SYSCALL_SEAID_SWITCH_WRITE           0xc504
#define SW_SYSCALL_SEAID_LIST_LEN_READ          0xc505
#define SW_SYSCALL_SEAID_SWITCH_READ            0xc506
#define SW_SYSCALL_SE_CONNECT_INFO_READ         0xc507
#define SW_SYSCALL_SE_CONNECT_INFO_WRITE        0xc508

#define SW_SYSCALL_TRNG_GENERATE_RANDOM         0xc601
#define SW_SYSCALL_SEC_HUK                      0xc602
#define SW_SYSCALL_SEC_AES_GCM                  0xc603
#define SW_SYSCALL_SEC_PRO_KEY                  0xc604

/* MSPE chinaDRM2.0 */
#define SW_SYSCALL_SEE_VIDEO_INIT             0xc900
#define SW_SYSCALL_SEE_VIDEO_UPDATE           0xc901
#define SW_SYSCALL_SEE_VIDEO_DOFINAL          0xc902
#define SW_SYSCALL_SEE_VIDEO_DEINIT           0xc903

/* sec for router */
#define SW_SYSCALL_SEC_DERIVEKEY                0xf603
#define SW_SYSCALL_SEC_RND_GENERATEVECTOR       0xf604

/* CRYPTO HAL */
#define SW_SYSCALL_CRYPTO_BASE                  0xc700
#define SW_SYSCALL_CRYPTO_GET_CTX_SIZE          0xc701
#define SW_SYSCALL_CRYPTO_CTX_COPY              0xc702
#define SW_SYSCALL_CRYPTO_HASH_INIT             0xc703
#define SW_SYSCALL_CRYPTO_HASH_UPDATE           0xc704
#define SW_SYSCALL_CRYPTO_HASH_DOFINAL          0xc705
#define SW_SYSCALL_CRYPTO_HASH                  0xc706
#define SW_SYSCALL_CRYPTO_HMAC_INIT             0xc707
#define SW_SYSCALL_CRYPTO_HMAC_UPDATE           0xc708
#define SW_SYSCALL_CRYPTO_HMAC_DOFINAL          0xc709
#define SW_SYSCALL_CRYPTO_HMAC                  0xc70a
#define SW_SYSCALL_CRYPTO_CIPHER_INIT           0xc70b
#define SW_SYSCALL_CRYPTO_CIPHER_UPDATE         0xc70c
#define SW_SYSCALL_CRYPTO_CIPHER_DOFINAL        0xc70d
#define SW_SYSCALL_CRYPTO_CIPHER                0xc70e
#define SW_SYSCALL_CRYPTO_AE_INIT               0xc70f
#define SW_SYSCALL_CRYPTO_AE_UPDATE_AAD         0xc710
#define SW_SYSCALL_CRYPTO_AE_UPDATE             0xc711
#define SW_SYSCALL_CRYPTO_AE_ENC_FINAL          0xc712
#define SW_SYSCALL_CRYPTO_AE_DEC_FINAL          0xc713
#define SW_SYSCALL_CRYPTO_RSA_GENERATE_KEYPAIR  0xc714
#define SW_SYSCALL_CRYPTO_RSA_ENCRYPT           0xc715
#define SW_SYSCALL_CRYPTO_RSA_DECRYPT           0xc716
#define SW_SYSCALL_CRYPTO_RSA_SIGN_DIGEST       0xc717
#define SW_SYSCALL_CRYPTO_RSA_VERIFY_DIGEST     0xc718
#define SW_SYSCALL_CRYPTO_ECC_GENERATE_KEYPAIR  0xc719
#define SW_SYSCALL_CRYPTO_ECC_ENCRYPT           0xc71a
#define SW_SYSCALL_CRYPTO_ECC_DECRYPT           0xc71b
#define SW_SYSCALL_CRYPTO_ECC_SIGN_DIGEST       0xc71c
#define SW_SYSCALL_CRYPTO_ECC_VERIFY_DIGEST     0xc71d
#define SW_SYSCALL_CRYPTO_ECDH_DERIVE_KEY       0xc71e
#define SW_SYSCALL_CRYPTO_DH_GENERATE_KEY       0xc71f
#define SW_SYSCALL_CRYPTO_DH_DERIVE_KEY         0xc720
#define SW_SYSCALL_CRYPTO_GENERATE_RANDOM       0xc721
#define SW_SYSCALL_CRYPTO_DERIVE_ROOT_KEY       0xc722
#define SW_SYSCALL_CRYPTO_PBKDF2                0xc723
#define SW_SYSCALL_CRYPTO_GET_DRV_ABILITY       0xc724
#define SW_SYSCALL_CRYPTO_GET_ENTROPY           0xc725
#define SW_SYSCALL_CRYPTO_MAX                   0xc726

/* syscall id for get cert from share mem */
#define SW_SYSCALL_GET_CERT                     0xc730

/* gatekeeper key factor */
#define SW_SYSCALL_ADD_KEY_FACTOR               0xc801
#define SW_SYSCALL_DELETE_KEY_FACTOR            0xc802
#define SW_SYSCALL_GET_KEY_FACTOR               0xc803
#endif /* DRIVERS_SRE_SYSCALLS_ID_H */
