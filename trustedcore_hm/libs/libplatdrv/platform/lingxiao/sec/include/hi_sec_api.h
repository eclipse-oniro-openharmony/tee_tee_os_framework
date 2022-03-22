/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: 加解密引擎驱动头文件
 * Author: ouweiquan 00302765
 * Create: 2016-12-24
 * History: 2019-1-29 hsan code restyle
 */

#ifndef __HI_SEC_API_H__
#define __HI_SEC_API_H__

#define HI_RNG_DATALEN    32
#define HI_KDF_PASSWD_LEN 32
#define HI_KDF_SALT_LEN   16
#define HI_KDF_DK_LEN     32
#define HI_KDF_ITER_COUNT 1000

struct hi_sec_trng {
	unsigned char rng[HI_RNG_DATALEN];
};

struct hi_sec_pbkdf2 {
	unsigned int passwd_len;                /* in 用户命令长度 */
	unsigned int salt_len;                  /* in 盐值的长度 */
	unsigned int iter;                      /* in 迭代次数 */
	unsigned int dk_len;
	unsigned char passwd[HI_KDF_PASSWD_LEN]; /* in 用户口令 */
	unsigned char salt[HI_KDF_SALT_LEN];     /* in 盐值 */
	unsigned char dk[HI_KDF_DK_LEN];         /* out 派生秘钥 */
};

struct hi_sec_kdf_internal {
	unsigned int iter;                   /* in 迭代次数 */
	unsigned int key_len;                /* in 密钥长度 */
	unsigned char key[HI_KDF_PASSWD_LEN]; /* in 原始密钥 */
    unsigned int dk_len;
    unsigned char dk[HI_KDF_DK_LEN];     /* out 派生秘钥 */
};

enum hi_sec_key_src {
	HI_SEC_KEY_SRC_BD = 0,
	HI_SEC_KEY_SRC_HUK,
	HI_SEC_KEY_SRC_KDF,
};

enum hi_sec_aes_cipher_e {
	HI_SEC_CIPHER_AES_ECB_E = 0,
	HI_SEC_CIPHER_AES_CBC_E,
	HI_SEC_CIPHER_AES_CCM_E,
	HI_SEC_CIPHER_AES_GCM_E,
	HI_SEC_CIPHER_AES_XTS_E,
	HI_SEC_CIPHER_AES_CTR_E,
};

enum hi_sec_hash_e {
	HI_SEC_HASH_SHA1 = 1,
	HI_SEC_HASH_SHA256,
	HI_SEC_HASH_SHA384,
	HI_SEC_HASH_SHA512,
};

enum hi_sec_hmac_e {
	HI_SEC_HMAC_SHA1 = 7,
	HI_SEC_HMAC_SHA256,
	HI_SEC_HMAC_SHA384,
	HI_SEC_HMAC_SHA512,
};

struct hi_sec_aes_cipher_req {
	enum hi_sec_key_src key_src;     /* 密钥来源 */
	unsigned char *key;                  /* 密钥 */
	unsigned int key_len;               /* 密钥长度 */
	unsigned char *iv;                   /* IV值 */
	unsigned int iv_len;                /* IV长度 */
	unsigned char *src;                  /* 源数据，解密时要包含认证数据 */
	unsigned int src_len;               /* 源数据长度 */
	unsigned char *dst;                  /* 目的数据 */
	unsigned int dst_len;               /* 目的数据长度 */
	enum hi_sec_aes_cipher_e cipher; /* 算法 */
};

struct hi_sec_aes_xcm_req {
	enum hi_sec_key_src key_src; /* 密钥来源 */
	unsigned char *key;              /* 密钥 */
	unsigned int key_len;           /* 密钥长度 */
	unsigned char *iv;               /* IV值 */
	unsigned int iv_len;            /* IV长度 */
	unsigned char *auth;             /* 认证数据 */
	unsigned int auth_len;          /* 认证数据长度 */
	unsigned int auth_tag_size;     /* 认证TAG长度 */
	unsigned char *src;              /* 源数据，解密时要包含认证数据 */
	unsigned int src_len;           /* 源数据长度 */
	unsigned char *dst;              /* 目的数据，加密时要预留认证数据写入空间，实际长度是dstLen + authTagSize */
	unsigned int dst_len;           /* 目的数据长度 */
};

struct hi_sec_hash_req {
	unsigned char *src;          /* 源数据 */
	unsigned int src_len;       /* 源数据长度 */
	unsigned char *auth;         /* 认证结果数据 */
	unsigned int auth_len;      /* 认证数据长度 */
	enum hi_sec_hash_e hash;
};

struct hi_sec_hmac_req {
	unsigned char *key;              /* 密钥 */
	unsigned int key_len;           /* 密钥长度 */
	unsigned char *src;              /* 源数据 */
	unsigned int src_len;           /* 源数据长度 */
	unsigned char *auth;             /* 认证结果数据 */
	unsigned int auth_len;          /* 认证数据长度 */
	enum hi_sec_hmac_e hmac;
};

struct hi_sec_rsa_req {
	unsigned char *e;      /* inout 公钥e */
	unsigned char *d;      /* inout 私钥d */
	unsigned char *n;      /* inout 密钥n */
	unsigned char *src;    /* in 源数据 */
	unsigned char *dst;    /* out 目的数据 */
	unsigned int key_len; /* in 密钥长度 */
	unsigned int einput;  /* in 密钥派生 是否需要输入公钥e */
};

struct hi_sec_ecdsa_req {
	unsigned char *d;      /* inout 私钥d */
	unsigned char *m;      /* in 源数据 */
	unsigned char *qx;     /* inout 公钥Q的X轴 */
	unsigned char *qy;     /* inout 公钥Q的Y轴 */
	unsigned char *sx;     /* out 目的数据S的X轴 */
	unsigned char *sy;     /* out 目的数据S的Y轴 */
	unsigned int key_len; /* in 密钥长度 */
};

struct hi_sec_dh_req {
	unsigned char *e;      /* in 大数e */
	unsigned char *g;      /* in 大数g */
	unsigned char *n;      /* in 大数n */
	unsigned char *dst;    /* out 派生密钥 */
	unsigned int key_len; /* in 密钥长度 */
};

int hi_sec_aes_encrypt(struct hi_sec_aes_cipher_req *req);
int hi_sec_aes_decrypt(struct hi_sec_aes_cipher_req *req);

int hi_sec_ccm_encrypt(struct hi_sec_aes_xcm_req *req);
int hi_sec_ccm_decrypt(struct hi_sec_aes_xcm_req *req);
int hi_sec_gcm_encrypt(struct hi_sec_aes_xcm_req *req);
int hi_sec_gcm_decrypt(struct hi_sec_aes_xcm_req *req);

int hi_sec_hash(struct hi_sec_hash_req *req);
int hi_sec_hmac(struct hi_sec_hmac_req *req);

int hi_sec_rsa_sign(struct hi_sec_rsa_req *req);
int hi_sec_rsa_verify(struct hi_sec_rsa_req *req);
int hi_sec_rsa_pri_encrypt(struct hi_sec_rsa_req *req);
int hi_sec_rsa_pri_decrypt(struct hi_sec_rsa_req *req);
int hi_sec_rsa_pub_encrypt(struct hi_sec_rsa_req *req);
int hi_sec_rsa_pub_decrypt(struct hi_sec_rsa_req *req);
int hi_sec_rsa_keygen(struct hi_sec_rsa_req *req);

int hi_sec_dh_keygen(struct hi_sec_dh_req *req);

int hi_sec_ecdsa_sign(struct hi_sec_ecdsa_req *req);
int hi_sec_ecdsa_verify(struct hi_sec_ecdsa_req *req);
int hi_sec_ecdsa_keygen(struct hi_sec_ecdsa_req *req);
int hi_sec_ecdsa_keychk(struct hi_sec_ecdsa_req *req);

/* 获取随机数 */
int hi_sec_trng_get(struct hi_sec_trng *rng);

/* kdf设备秘钥派生 */
unsigned int hi_kdf_to_dev(struct hi_sec_pbkdf2 *para);

/* kdf存储秘钥派生 */
unsigned int hi_kdf_to_store(struct hi_sec_kdf_internal *para);

#endif
