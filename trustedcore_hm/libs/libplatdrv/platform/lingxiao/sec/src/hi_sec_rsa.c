/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: rsa模块
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11初稿完成
 *          2019-1-31 hsan code restyle
 */

#include <hisilicon/chip/level_2/hi_sdk_l2.h>

#include "hi_sec_api.h"
#include "hi_sec_pke.h"

/* c=m**e mod n; e是私钥d */
static hi_int32 hi_sec_rsa_pri(struct hi_sec_rsa_req *pri_req)
{
	struct hi_pke_modexp_s modexp;

	modexp.m = pri_req->src;
	modexp.e = pri_req->d;
	modexp.n = pri_req->n;
	modexp.len = pri_req->key_len;
	modexp.c = pri_req->dst;
	return hi_sec_pke_modexp(&modexp, HI_SEC_AEALG_RSA);
}

/* c=m**e mod n; e是公钥e */
static hi_int32 hi_sec_rsa_pub(struct hi_sec_rsa_req *pub_req)
{
	struct hi_pke_modexp_s modexp;

	modexp.m = pub_req->src;
	modexp.e = pub_req->e;
	modexp.n = pub_req->n;
	modexp.len = pub_req->key_len;
	modexp.c = pub_req->dst;
	return hi_sec_pke_modexp(&modexp, HI_SEC_AEALG_RSA);
}

/*
 * RSA签名，类似于私钥加密
 * c=m**e mod n; m是明文；e是私钥d；n是密钥n；
 */
hi_int32 hi_sec_rsa_sign(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pri(req);
}

/*
 * RSA验签，类似于公钥解密
 * c=m**e mod n; m是密文；e是公钥e；n是密钥n；
 */
hi_int32 hi_sec_rsa_verify(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pub(req);
}

/*
 * RSA私钥加密
 * c=m**e mod n; m是明文；e是私钥d；n是密钥n；
 */
hi_int32 hi_sec_rsa_pri_encrypt(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pri(req);
}

/*
 * RSA私钥解密
 * c=m**e mod n; m是密文；e是私钥d；n是密钥n；
 */
hi_int32 hi_sec_rsa_pri_decrypt(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pri(req);
}

/*
 * RSA公钥加密
 * c=m**e mod n; m是明文；e是公钥e；n是密钥n；
 */
hi_int32 hi_sec_rsa_pub_encrypt(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pub(req);
}

/*
 * RSA公钥解密
 * c=m**e mod n; m是密文；e是公钥e；n是密钥n；
 */
hi_int32 hi_sec_rsa_pub_decrypt(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pub(req);
}

/* RSA密钥产生 */
hi_int32 hi_sec_rsa_keygen(struct hi_sec_rsa_req *req)
{
	return hi_sec_pke_rsa_keygen(req);
}

/* DH密钥产生 dst=g**e mod n */
hi_int32 hi_sec_dh_keygen(struct hi_sec_dh_req *req)
{
	struct hi_pke_modexp_s modexp;

	modexp.c = req->dst;
	modexp.m = req->g;
	modexp.e = req->e;
	modexp.n = req->n;
	modexp.len = req->key_len;

	return hi_sec_pke_modexp(&modexp, HI_SEC_AEALG_DH);
}