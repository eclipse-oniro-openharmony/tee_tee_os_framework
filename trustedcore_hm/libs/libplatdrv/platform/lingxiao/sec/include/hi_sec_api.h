/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: �ӽ�����������ͷ�ļ�
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
	unsigned int passwd_len;                /* in �û������ */
	unsigned int salt_len;                  /* in ��ֵ�ĳ��� */
	unsigned int iter;                      /* in �������� */
	unsigned int dk_len;
	unsigned char passwd[HI_KDF_PASSWD_LEN]; /* in �û����� */
	unsigned char salt[HI_KDF_SALT_LEN];     /* in ��ֵ */
	unsigned char dk[HI_KDF_DK_LEN];         /* out ������Կ */
};

struct hi_sec_kdf_internal {
	unsigned int iter;                   /* in �������� */
	unsigned int key_len;                /* in ��Կ���� */
	unsigned char key[HI_KDF_PASSWD_LEN]; /* in ԭʼ��Կ */
    unsigned int dk_len;
    unsigned char dk[HI_KDF_DK_LEN];     /* out ������Կ */
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
	enum hi_sec_key_src key_src;     /* ��Կ��Դ */
	unsigned char *key;                  /* ��Կ */
	unsigned int key_len;               /* ��Կ���� */
	unsigned char *iv;                   /* IVֵ */
	unsigned int iv_len;                /* IV���� */
	unsigned char *src;                  /* Դ���ݣ�����ʱҪ������֤���� */
	unsigned int src_len;               /* Դ���ݳ��� */
	unsigned char *dst;                  /* Ŀ������ */
	unsigned int dst_len;               /* Ŀ�����ݳ��� */
	enum hi_sec_aes_cipher_e cipher; /* �㷨 */
};

struct hi_sec_aes_xcm_req {
	enum hi_sec_key_src key_src; /* ��Կ��Դ */
	unsigned char *key;              /* ��Կ */
	unsigned int key_len;           /* ��Կ���� */
	unsigned char *iv;               /* IVֵ */
	unsigned int iv_len;            /* IV���� */
	unsigned char *auth;             /* ��֤���� */
	unsigned int auth_len;          /* ��֤���ݳ��� */
	unsigned int auth_tag_size;     /* ��֤TAG���� */
	unsigned char *src;              /* Դ���ݣ�����ʱҪ������֤���� */
	unsigned int src_len;           /* Դ���ݳ��� */
	unsigned char *dst;              /* Ŀ�����ݣ�����ʱҪԤ����֤����д��ռ䣬ʵ�ʳ�����dstLen + authTagSize */
	unsigned int dst_len;           /* Ŀ�����ݳ��� */
};

struct hi_sec_hash_req {
	unsigned char *src;          /* Դ���� */
	unsigned int src_len;       /* Դ���ݳ��� */
	unsigned char *auth;         /* ��֤������� */
	unsigned int auth_len;      /* ��֤���ݳ��� */
	enum hi_sec_hash_e hash;
};

struct hi_sec_hmac_req {
	unsigned char *key;              /* ��Կ */
	unsigned int key_len;           /* ��Կ���� */
	unsigned char *src;              /* Դ���� */
	unsigned int src_len;           /* Դ���ݳ��� */
	unsigned char *auth;             /* ��֤������� */
	unsigned int auth_len;          /* ��֤���ݳ��� */
	enum hi_sec_hmac_e hmac;
};

struct hi_sec_rsa_req {
	unsigned char *e;      /* inout ��Կe */
	unsigned char *d;      /* inout ˽Կd */
	unsigned char *n;      /* inout ��Կn */
	unsigned char *src;    /* in Դ���� */
	unsigned char *dst;    /* out Ŀ������ */
	unsigned int key_len; /* in ��Կ���� */
	unsigned int einput;  /* in ��Կ���� �Ƿ���Ҫ���빫Կe */
};

struct hi_sec_ecdsa_req {
	unsigned char *d;      /* inout ˽Կd */
	unsigned char *m;      /* in Դ���� */
	unsigned char *qx;     /* inout ��ԿQ��X�� */
	unsigned char *qy;     /* inout ��ԿQ��Y�� */
	unsigned char *sx;     /* out Ŀ������S��X�� */
	unsigned char *sy;     /* out Ŀ������S��Y�� */
	unsigned int key_len; /* in ��Կ���� */
};

struct hi_sec_dh_req {
	unsigned char *e;      /* in ����e */
	unsigned char *g;      /* in ����g */
	unsigned char *n;      /* in ����n */
	unsigned char *dst;    /* out ������Կ */
	unsigned int key_len; /* in ��Կ���� */
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

/* ��ȡ����� */
int hi_sec_trng_get(struct hi_sec_trng *rng);

/* kdf�豸��Կ���� */
unsigned int hi_kdf_to_dev(struct hi_sec_pbkdf2 *para);

/* kdf�洢��Կ���� */
unsigned int hi_kdf_to_store(struct hi_sec_kdf_internal *para);

#endif
