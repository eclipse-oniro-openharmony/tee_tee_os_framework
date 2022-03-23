/**
 * @file   : common_rsa.h
 * @brief  :rsa common data
 * @par    : Copyright(c) 2018-2034, HUAWEI Technology Co., Ltd.
 * @date   : 2018/03/03
 * @author : z00358830
 * @note   :RSA BIT WIDTH
 */
#ifndef __COMMON_RSA_H__
#define __COMMON_RSA_H__
#include <common_def.h>

#define RSA_WIDTH_STEP                   (64)
#define RSA_WIDTH_256                    (256)
#define RSA_WIDTH_384                    (384)
#define RSA_WIDTH_512                    (512)
#define RSA_WIDTH_576                    (576)
#define RSA_WIDTH_768                    (768)
#define RSA_WIDTH_1024                   (1024)
#define RSA_WIDTH_1152                   (1152)
#define RSA_WIDTH_1976                   (1976)
#define RSA_WIDTH_1984                   (1984)
#define RSA_WIDTH_2048                   (2048)
#define RSA_WIDTH_3072                   (3072)
#define RSA_WIDTH_4096                   (4096)
#define RSA_WIDTH_MAX                    (RSA_WIDTH_4096)
#define RSA_WIDTH_8192                   (8192)
#define RSA_WIDTH_CLRMAX                 (0x1F)

typedef enum {
	RSA_ID_1    = 1,
	RSA_ID_2    = 2,
	RSA_ID_3    = 3,
	RSA_ID_MAX = 4,
} rsa_id_e;

#endif /* end of __COMMON_RSA_H__ */
