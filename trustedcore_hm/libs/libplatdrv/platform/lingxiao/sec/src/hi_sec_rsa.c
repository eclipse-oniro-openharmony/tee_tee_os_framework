/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: rsaģ��
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11�������
 *          2019-1-31 hsan code restyle
 */

#include <hisilicon/chip/level_2/hi_sdk_l2.h>

#include "hi_sec_api.h"
#include "hi_sec_pke.h"

/* c=m**e mod n; e��˽Կd */
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

/* c=m**e mod n; e�ǹ�Կe */
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
 * RSAǩ����������˽Կ����
 * c=m**e mod n; m�����ģ�e��˽Կd��n����Կn��
 */
hi_int32 hi_sec_rsa_sign(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pri(req);
}

/*
 * RSA��ǩ�������ڹ�Կ����
 * c=m**e mod n; m�����ģ�e�ǹ�Կe��n����Կn��
 */
hi_int32 hi_sec_rsa_verify(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pub(req);
}

/*
 * RSA˽Կ����
 * c=m**e mod n; m�����ģ�e��˽Կd��n����Կn��
 */
hi_int32 hi_sec_rsa_pri_encrypt(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pri(req);
}

/*
 * RSA˽Կ����
 * c=m**e mod n; m�����ģ�e��˽Կd��n����Կn��
 */
hi_int32 hi_sec_rsa_pri_decrypt(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pri(req);
}

/*
 * RSA��Կ����
 * c=m**e mod n; m�����ģ�e�ǹ�Կe��n����Կn��
 */
hi_int32 hi_sec_rsa_pub_encrypt(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pub(req);
}

/*
 * RSA��Կ����
 * c=m**e mod n; m�����ģ�e�ǹ�Կe��n����Կn��
 */
hi_int32 hi_sec_rsa_pub_decrypt(struct hi_sec_rsa_req *req)
{
	return hi_sec_rsa_pub(req);
}

/* RSA��Կ���� */
hi_int32 hi_sec_rsa_keygen(struct hi_sec_rsa_req *req)
{
	return hi_sec_pke_rsa_keygen(req);
}

/* DH��Կ���� dst=g**e mod n */
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