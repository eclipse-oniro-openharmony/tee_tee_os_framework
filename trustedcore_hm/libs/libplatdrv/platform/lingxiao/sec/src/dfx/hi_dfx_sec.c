/******************************************************************************

          版权所有 (C), 2008-2018, 海思半导体有限公司

******************************************************************************
  文件名称: hi_dfx_sec.c
  功能描述: 安全模块DFX功能
  版本描述: V1.0

  创建日期: D2017_10_27
  创建作者: ouweiquan 00302765

  修改记录:
            生成初稿.
******************************************************************************/

#include <hisilicon/chip/level_2/hi_sdk_l2.h>
#include <linux/time.h>
#include "hi_sec_drv.h"
#include "hi_sec_pke.h"
#include "hi_sec_aes.h"
#include "hi_sec_hash.h"
#include "hi_sec_api.h"
#include "hi_dfx_sec.h"

typedef hi_int32(* hi_sec_aealg_func)(struct hi_sec_aealg_s *aealg);

static hi_int32 hi_sec_aealg_rsa_pri(struct hi_sec_aealg_s *aealg);
static hi_int32 hi_sec_aealg_rsa_pub(struct hi_sec_aealg_s *aealg);
static hi_int32 hi_sec_aealg_rsa_keygen(struct hi_sec_aealg_s *aealg);
static hi_int32 hi_sec_aealg_dh(struct hi_sec_aealg_s *aealg);
static hi_int32 hi_sec_aealg_ecdsa_sign(struct hi_sec_aealg_s *aealg);
static hi_int32 hi_sec_aealg_ecdsa_verif(struct hi_sec_aealg_s *aealg);
static hi_int32 hi_sec_aealg_ecdsa_keygen(struct hi_sec_aealg_s *aealg);
static hi_int32 hi_sec_aealg_ecdsa_keychk(struct hi_sec_aealg_s *aealg);

static hi_sec_aealg_func g_apfc_aealg[HI_SEC_AEALG_NUM][HI_SEC_AEALG_FUNC_NUM] = {
    {hi_sec_aealg_rsa_pri, hi_sec_aealg_rsa_pub, hi_sec_aealg_rsa_pub, hi_sec_aealg_rsa_pub, hi_sec_aealg_rsa_pri, hi_sec_aealg_rsa_pri, hi_sec_aealg_rsa_keygen,  HI_NULL},
    {HI_NULL, HI_NULL, HI_NULL, HI_NULL, HI_NULL, HI_NULL, hi_sec_aealg_dh, HI_NULL},
    {hi_sec_aealg_ecdsa_sign, hi_sec_aealg_ecdsa_verif, HI_NULL, HI_NULL, HI_NULL, HI_NULL, hi_sec_aealg_ecdsa_keygen, hi_sec_aealg_ecdsa_keychk},
};

static struct hi_dfx_sec_cmd_s g_dfx_sec_cmd = {1, 0, 0};

static hi_uchar8 *g_auth_name[HI_SEC_DRV_HASH_SM3_E + 1] = {
	"md5",          //HI_SEC_DRV_HASH_MD5_E = 0,
	"sha1",         //HI_SEC_DRV_HASH_SHA1_E,
	"sha256",       //HI_SEC_DRV_HASH_SHA256_E,
	"sha384",       //HI_SEC_DRV_HASH_SHA384_E,
	"sha512",       //HI_SEC_DRV_HASH_SHA512_E,
	"hmac(sm3)",    //HI_SEC_DRV_HASH_HMAC_SM3_E,
	"hmac(md5)",    //HI_SEC_DRV_HASH_HMAC_MD5_E,
	"hmac(sha1)",   //HI_SEC_DRV_HASH_HMAC_SHA1_E,
	"hmac(sha256)", //HI_SEC_DRV_HASH_HMAC_SHA256_E,
	"hmac(sha384)", //HI_SEC_DRV_HASH_HMAC_SHA384_E,
	"hmac(sha512)", //HI_SEC_DRV_HASH_HMAC_SHA512_E,
	"sm3",          //HI_SEC_DRV_HASH_SM3_E,
};

static hi_uchar8 *g_cipher_name[HI_SEC_DRV_CIPHER_SM4_CBC_E + 3] = {
	"ecb(aes)",         //HI_SEC_DRV_CIPHER_AES_ECB_E = 0,
	"cbc(aes)",         //HI_SEC_DRV_CIPHER_AES_CBC_E = 1,
	"ccm(aes)",         //HI_SEC_DRV_CIPHER_AES_CCM_E = 2,
	"gcm(aes)",         //HI_SEC_DRV_CIPHER_AES_GCM_E = 3,
	"xts(aes)",         //HI_SEC_DRV_CIPHER_AES_XTS_E = 4,
	"ctr(aes)",         //HI_SEC_DRV_CIPHER_AES_CTR_E = 5,
	"ecb(des)",         //HI_SEC_DRV_CIPHER_DES_ECB_E = 6,
	"cbc(des)",         //HI_SEC_DRV_CIPHER_DES_CBC_E = 7,
	"ecb(des3_ede)",    //HI_SEC_DRV_CIPHER_TDES_ECB_E = 8,
	"cbc(des3_ede)",    //HI_SEC_DRV_CIPHER_TDES_CBC_E = 9,
	"cbc(sm4)",         //HI_SEC_DRV_CIPHER_SM4_CBC_E = 10,
	"rfc4309(ccm(aes))",//11
	"rfc4106(gcm(aes))",//12
};


static hi_void hi_dfx_sec_time(struct timeval *time_start,
			       struct timeval *time_end)
{
	g_dfx_sec_cmd.time_s = time_end->tv_sec - time_start->tv_sec;

	if (time_end->tv_usec >= time_start->tv_usec) {
		g_dfx_sec_cmd.time_us = time_end->tv_usec - time_start->tv_usec;
	} else {
		if (g_dfx_sec_cmd.time_s > 0) {
			g_dfx_sec_cmd.time_s--;
			g_dfx_sec_cmd.time_us = 1000000 - time_start->tv_usec +
						   time_end->tv_usec;
		} else {
			g_dfx_sec_cmd.time_us = 0;
		}
	}

}

#if 0
/*****************************************************************************
函数名称: hi_dfx_sec_cmd_n_set
功能描述: 配置运算次数N
输入参数: hi_dfx_sec_cmd_s *pst_cmd
输出参数: NA
返 回 值: hi_uint32
*****************************************************************************/
hi_int32 hi_dfx_sec_cmd_n_set(hi_dfx_sec_cmd_s *pst_cmd)
{
	g_dfx_sec_cmd.n = pst_cmd->n;
	return HI_RET_SUCC;
}

/*****************************************************************************
函数名称: hi_dfx_sec_cmd_n_get
功能描述: 运算N次所花费的时间
输入参数: NA
输出参数: hi_dfx_sec_cmd_s *pst_cmd
返 回 值: hi_uint32
*****************************************************************************/
hi_int32 hi_dfx_sec_cmd_n_get(hi_dfx_sec_cmd_s *pst_cmd)
{
	pst_cmd->n = g_dfx_sec_cmd.n;
	pst_cmd->time_s = g_dfx_sec_cmd.time_s;
	pst_cmd->time_us = g_dfx_sec_cmd.time_us;
	return HI_RET_SUCC;
}

hi_int32 hi_dfx_sec_aealg_pointmultik_set(hi_sec_pke_dfx_s *pst_dfx)
{
	return hi_sec_aealg_pointmultik_set(pst_dfx);
}

hi_int32 hi_dfx_sec_aealg_pointmultik_get(hi_uint32 *pui_enable)
{
	return hi_sec_aealg_pointmultik_get(pui_enable);
}

hi_int32 hi_dfx_sec_aealg_sta_get(hi_sec_pke_sta_s *pst_sta)
{
	return hi_sec_aealg_sta_get(pst_sta);
}

hi_int32 hi_dfx_sec_alg_cnt_get(hi_sec_cnt_s *pst_cnt)
{
	return hi_sec_cnt_get(pst_cnt);
}

hi_int32 hi_dfx_sec_alg_sta_get(hi_sec_sta_s *pst_sta)
{
	return hi_sec_sta_get(pst_sta);
}
#endif

/* 命令行执行加解密算法 */
static hi_int32 hi_dfx_sec_enc_cmd(hi_uint32 encrypt,
				   hi_uint32 cipher, struct hi_sec_dfx_enc_s *enc)
{
	struct hi_sec_aes_cipher_req req;
	struct timeval time_start;
	struct timeval time_end;
	hi_uint32 index;
	hi_uchar8 *src = HI_NULL;
	hi_uchar8 *dst = HI_NULL;
	hi_uchar8 *key = HI_NULL;
	hi_uchar8 *iv = HI_NULL;
	hi_int32 ret;

	if (enc->cryptlen == 0 ||
	    enc->keylen == 0)
		return HI_RET_INVALID_PARA;

	src = (hi_uchar8 *)hi_malloc(enc->cryptlen * 2 + enc->keylen + HI_SEC_IV_SIZE);
	if (src == HI_NULL)
		return HI_RET_MALLOC_FAIL;

	dst = src + enc->cryptlen;
	key = dst + enc->cryptlen;
	iv = key + enc->keylen;

	if (hi_copy_from_user(src, enc->src, enc->cryptlen)) {
		hi_pke_systrace(HI_RET_FAIL, enc->cryptlen, 0, 0, 0);
		hi_free(src);
		return HI_RET_FAIL;
	}

	if (hi_copy_from_user(key, enc->key, enc->keylen)) {
		hi_pke_systrace(HI_RET_FAIL, enc->keylen, 0, 0, 0);
		hi_free(src);
		return HI_RET_FAIL;
	}

	if (hi_copy_from_user(iv, enc->iv, HI_SEC_IV_SIZE)) {
		hi_pke_systrace(HI_RET_FAIL, enc->iv[0], 0, 0, 0);
		hi_free(src);
		return HI_RET_FAIL;
	}

	req.key = key;
	req.key_len = enc->keylen;
	req.iv = iv;
	req.iv_len = HI_SEC_IV_SIZE;
	req.src = src;
	req.src_len = enc->cryptlen;
	req.dst = dst;
	req.dst_len = enc->cryptlen;
	req.cipher = cipher;
	req.key_src = enc->keymode;

	do_gettimeofday(&time_start);

	for (index = 0; index < g_dfx_sec_cmd.n; index++) {
		if (encrypt)
			ret = hi_sec_aes_encrypt(&req);
		else
			ret = hi_sec_aes_decrypt(&req);

		if (ret != HI_RET_SUCC) {
			hi_pke_systrace(HI_RET_FAIL, req.cipher, encrypt, 0, 0);
			hi_free(src);
			msleep(1);
			return HI_RET_FAIL;
		}
	}

	do_gettimeofday(&time_end);
	hi_dfx_sec_time(&time_start, &time_end);
	hi_printk("%s [%d]times: sec[%d] usec[%d]\n",
		  g_cipher_name[cipher], g_dfx_sec_cmd.n,
		  g_dfx_sec_cmd.time_s, g_dfx_sec_cmd.time_us);

	if (hi_copy_to_user(enc->dst, dst, enc->cryptlen)) {
		hi_free(src);
		return HI_RET_FAIL;
	}

	hi_free(src);
	return HI_RET_SUCC;
}

static hi_int32 hi_dfx_sec_digestsize_get(hi_uint32 auth)
{
	switch (auth) {
	case HI_SEC_DRV_HASH_SHA1_E:
		return HI_SHA1_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_SHA256_E:
		return HI_SHA256_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_SHA384_E:
		return HI_SHA384_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_SHA512_E:
		return HI_SHA512_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_HMAC_SHA1_E:
		return HI_SHA1_HMAC_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_HMAC_SHA256_E:
		return HI_SHA256_HMAC_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_HMAC_SHA384_E:
		return HI_SHA384_HMAC_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_HMAC_SHA512_E:
		return HI_SHA512_HMAC_DIGEST_SIZE;
	default:
		return HI_SHA1_HMAC_DIGEST_SIZE;
	}
}

/* 命令行执行HMAC认证算法 */
static hi_int32 hi_dfx_sec_hmac_cmd(hi_uint32 hmac,
				    struct hi_sec_dfx_auth_s *auth)
{
	struct hi_sec_hmac_req req;
	struct timeval time_start;
	struct timeval time_end;
	hi_uint32 index;
	hi_uchar8 *assoc = HI_NULL;
	hi_uchar8 *digest = HI_NULL;
	hi_uchar8 *akey = HI_NULL;
	hi_uint32 digestsize;
	hi_int32 ret;

	if (auth->assoclen == 0 || auth->akeylen == 0)
		return HI_RET_INVALID_PARA;

	digestsize = hi_dfx_sec_digestsize_get(hmac);
	assoc = (hi_uchar8 *)hi_malloc(auth->assoclen + auth->akeylen +
				       digestsize);
	if (assoc == HI_NULL)
		return HI_RET_MALLOC_FAIL;

	digest = assoc + auth->assoclen;
	akey = digest + digestsize;

	if (hi_copy_from_user(assoc, auth->assoc, auth->assoclen)) {
		hi_free(assoc);
		return HI_RET_FAIL;
	}

	if (hi_copy_from_user(akey, auth->akey, auth->akeylen)) {
		hi_free(assoc);
		return HI_RET_FAIL;
	}

	req.key = akey;
	req.key_len = auth->akeylen;
	req.src = assoc;
	req.src_len = auth->assoclen;
	req.auth = digest;
	req.auth_len = digestsize;
	req.hmac = hmac;	// 
	do_gettimeofday(&time_start);

	for (index = 0; index < g_dfx_sec_cmd.n; index++) {
		ret = hi_sec_hmac(&req);
		if (ret != HI_RET_SUCC) {
			msleep(1);
			hi_free(assoc);
			return HI_RET_FAIL;
		}
	}

	do_gettimeofday(&time_end);
	hi_dfx_sec_time(&time_start, &time_end);
	hi_printk("%s [%d]times: sec[%d] usec[%d]\n",
		  g_auth_name[hmac], g_dfx_sec_cmd.n,
		  g_dfx_sec_cmd.time_s, g_dfx_sec_cmd.time_us);

	if (hi_copy_to_user(auth->hash, digest, digestsize)) {
		hi_free(assoc);
		return HI_RET_FAIL;
	}

	hi_free(assoc);
	return HI_RET_SUCC;
}

/* 命令行执行HASH认证算法 */
static hi_int32 hi_dfx_sec_hash_cmd(hi_uint32 hash,
				    struct hi_sec_dfx_auth_s *auth)
{
	struct hi_sec_hash_req req;
	struct timeval time_start;
	struct timeval time_end;
	hi_uint32 index;
	hi_uchar8 *assoc = HI_NULL;
	hi_uchar8 *digest = HI_NULL;
	hi_uint32 digestsize;
	hi_int32 ret;

	if (auth->assoclen == 0) { //  || auth->akeylen == 0
		hi_secdrv_systrace(HI_RET_INVALID_PARA, auth->assoclen, auth->akeylen, 0, 0);
		return HI_RET_INVALID_PARA;
	}
	digestsize = hi_dfx_sec_digestsize_get(hash);
	assoc = (hi_uchar8 *)hi_malloc(auth->assoclen + digestsize);
	if (assoc == HI_NULL)
		return HI_RET_MALLOC_FAIL;

	digest = assoc + auth->assoclen;

	if (hi_copy_from_user(assoc, auth->assoc, auth->assoclen)) {
		hi_free(assoc);
		return HI_RET_FAIL;
	}

	req.src = assoc;
	req.src_len = auth->assoclen;
	req.auth = digest;
	req.auth_len = digestsize;
	req.hash = hash;	//
	do_gettimeofday(&time_start);

	for (index = 0; index < g_dfx_sec_cmd.n; index++) {
		ret = hi_sec_hash(&req);
		if (ret != HI_RET_SUCC) {
			msleep(1);
			hi_free(assoc);
			return HI_RET_FAIL;
		}
	}

	do_gettimeofday(&time_end);
	hi_dfx_sec_time(&time_start, &time_end);
	hi_printk("%s [%d]times: sec[%d] usec[%d]\n",
		  g_auth_name[hash], g_dfx_sec_cmd.n,
		  g_dfx_sec_cmd.time_s, g_dfx_sec_cmd.time_us);

	if (hi_copy_to_user(auth->hash, digest, digestsize)) {
		hi_free(assoc);
		return HI_RET_FAIL;
	}

	hi_free(assoc);
	return HI_RET_SUCC;
}

static hi_int32 hi_dfx_sec_xcm_encrypt(hi_uint32 cipher, struct hi_sec_aes_xcm_req *req)
{
	if (cipher == HI_SEC_DRV_CIPHER_AES_CCM_E)
		return hi_sec_ccm_encrypt(req);
	else if (cipher == HI_SEC_DRV_CIPHER_AES_GCM_E)
		return hi_sec_gcm_encrypt(req);

	return HI_RET_INVALID_PARA;
}

static hi_int32 hi_dfx_sec_xcm_decrypt(hi_uint32 cipher, struct hi_sec_aes_xcm_req *req)
{
	if (cipher == HI_SEC_DRV_CIPHER_AES_CCM_E)
		return hi_sec_ccm_decrypt(req);
	else if (cipher == HI_SEC_DRV_CIPHER_AES_GCM_E)
		return hi_sec_gcm_decrypt(req);

	return HI_RET_INVALID_PARA;
}

/* 命令行执行认证+加解密算法 */
static hi_int32 hi_dfx_sec_authenc_cmd(hi_uint32 enc,
		hi_uint32 cipher, hi_uint32 hash, struct hi_sec_dfx_authenc_s *authenc)
{
	struct hi_sec_aes_xcm_req req;
	struct timeval time_start;
	struct timeval time_end;
	hi_uint32 index;
	hi_uchar8 *src = HI_NULL;
	hi_uchar8 *dst = HI_NULL;
	hi_uchar8 *assoc = HI_NULL;
	hi_uchar8 *key = HI_NULL;
	hi_uchar8 *akey = HI_NULL;
	hi_uchar8 *iv = HI_NULL;
	hi_int32 ret;

	if (authenc->keylen == 0)
		return HI_RET_INVALID_PARA;

	if (cipher != HI_SEC_DRV_CIPHER_AES_CCM_E &&
	    cipher != HI_SEC_DRV_CIPHER_AES_GCM_E)
		return HI_RET_INVALID_PARA;

	src = (hi_uchar8 *)hi_malloc(authenc->cryptlen * 2 +
				     authenc->assoclen + authenc->authsize +
				     authenc->keylen + authenc->akeylen + authenc->ivsize);
	if (src == HI_NULL)
		return HI_RET_MALLOC_FAIL;

	dst = src + authenc->cryptlen;
	assoc = dst + authenc->cryptlen + authenc->authsize;
	key = assoc + authenc->assoclen;
	akey = key + authenc->keylen;
	iv = akey + authenc->akeylen;

	if (enc) {
		if (authenc->cryptlen > 0) {
			if (hi_copy_from_user(src, authenc->src, authenc->cryptlen)) {
				hi_free(src);
				return HI_RET_FAIL;
			}
		}
	} else {
		if (authenc->cryptlen > 0 || authenc->authsize > 0) {
			if (hi_copy_from_user(dst, authenc->dst,
					      authenc->cryptlen + authenc->authsize)) {
				hi_free(src);
				return HI_RET_FAIL;
			}
		}
	}

	if (authenc->assoclen > 0) {
		if (hi_copy_from_user(assoc, authenc->assoc,
				      authenc->assoclen)) {
			hi_free(src);
			return HI_RET_FAIL;
		}
	}

	if (hi_copy_from_user(key, authenc->key, authenc->keylen)) {
		hi_free(src);
		return HI_RET_FAIL;
	}

	if (authenc->akeylen > 0) {
		if (hi_copy_from_user(akey, authenc->akey,
				      authenc->akeylen)) {
			hi_free(src);
			return HI_RET_FAIL;
		}
	}

	if (authenc->ivsize > 0) {
		if (hi_copy_from_user(iv, authenc->iv, authenc->ivsize)) {
			hi_free(src);
			return HI_RET_FAIL;
		}
	}

	req.key = key;
	req.key_len = authenc->keylen;
	req.iv = iv;
	req.iv_len = authenc->ivsize;
	req.auth = assoc;
	req.auth_len = authenc->assoclen;
	req.auth_tag_size = authenc->authsize;
	req.src = src;
	req.src_len = authenc->cryptlen;
	req.dst = dst;
	req.dst_len = authenc->cryptlen;

	do_gettimeofday(&time_start);

	for (index = 0; index < g_dfx_sec_cmd.n; index++) {
		if (enc) {
			ret = hi_dfx_sec_xcm_encrypt(cipher, &req);
		} else {
			ret = hi_dfx_sec_xcm_decrypt(cipher, &req);
		}

		if (ret != HI_RET_SUCC) {
			hi_free(src);
			msleep(1);
			return HI_RET_FAIL;
		}
	}

	do_gettimeofday(&time_end);
	hi_dfx_sec_time(&time_start, &time_end);
	hi_printk("%s [%d]times: sec[%d] usec[%d]\n",
		  g_cipher_name[cipher], g_dfx_sec_cmd.n, g_dfx_sec_cmd.time_s,
		  g_dfx_sec_cmd.time_us);

	if (enc) {
		if (authenc->cryptlen > 0 || authenc->authsize > 0) {
			if (hi_copy_to_user(authenc->dst, dst,
					    authenc->cryptlen + authenc->authsize)) {
				hi_free(src);
				return HI_RET_FAIL;
			}
		}
	} else {
		if (authenc->cryptlen > 0) {
			if (hi_copy_to_user(authenc->src, src, authenc->cryptlen)) {
				hi_free(src);
				return HI_RET_FAIL;
			}
		}
	}

	hi_free(src);
	return HI_RET_SUCC;
}

/* 命令行执行算法 */
hi_int32 hi_dfx_sec_alg_cmd(struct hi_sec_dfx_alg_cmd_s *cmd)
{
	hi_int32 ret;

	if (cmd->cipher == HI_SEC_DRV_CIPHER_AES_CCM_E ||
	    cmd->cipher == HI_SEC_DRV_CIPHER_AES_GCM_E)
		ret = hi_dfx_sec_authenc_cmd(cmd->enc, cmd->cipher,
					     cmd->hash, &cmd->param.authenc);
	else if (cmd->cipher <= HI_SEC_DRV_CIPHER_SM4_CBC_E)
		ret = hi_dfx_sec_enc_cmd(cmd->enc, cmd->cipher, &cmd->param.enc);
	else if (cmd->hash >= HI_SEC_DRV_HASH_HMAC_SHA1_E && cmd->hash <= HI_SEC_DRV_HASH_HMAC_SHA512_E)
		ret = hi_dfx_sec_hmac_cmd(cmd->hash, &cmd->param.auth);
	else if (cmd->hash >= HI_SEC_DRV_HASH_SHA1_E && cmd->hash <= HI_SEC_DRV_HASH_SHA512_E)
		ret = hi_dfx_sec_hash_cmd(cmd->hash, &cmd->param.auth);
	else
		return HI_RET_INVALID_PARA;

	return ret;
}
HI_EXPORT_IPC11(hi_dfx_sec_alg_cmd);

/* SEC RSA 私钥运算应用接口 */
static hi_int32 hi_sec_aealg_rsa_pri(struct hi_sec_aealg_s *aealg)
{
	hi_int32 ret;
	hi_uchar8 *data = HI_NULL;
	hi_uint32 keylen = aealg->param.rsa.key_len;
	struct hi_sec_rsa_req req;

    if (HI_SEC_PKE_RSA_1024BIT != keylen &&
        HI_SEC_PKE_RSA_2048BIT != keylen &&
        HI_SEC_PKE_RSA_3072BIT != keylen &&
        HI_SEC_PKE_RSA_4096BIT != keylen) {
        hi_pke_systrace(HI_RET_INVALID_PARA, keylen , 0, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    if (HI_NULL == aealg->param.rsa.src ||
        HI_NULL == aealg->param.rsa.d ||
        HI_NULL == aealg->param.rsa.e ||
        HI_NULL == aealg->param.rsa.n ||
        HI_NULL == aealg->param.rsa.dst) {
        hi_pke_systrace(HI_RET_NULLPTR, 0 , 0, 0, 0);
        return HI_RET_NULLPTR;
    }

    data = hi_malloc(HI_SEC_PKE_RSA_MAXLEN * 5);
    if (HI_NULL == data) {
        hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
        return HI_RET_MALLOC_FAIL;
    }

	req.src = data;
	req.d = req.src + HI_SEC_PKE_RSA_MAXLEN;
	req.n = req.d + HI_SEC_PKE_RSA_MAXLEN;
	req.dst = req.n + HI_SEC_PKE_RSA_MAXLEN;
	req.e = req.dst + HI_SEC_PKE_RSA_MAXLEN;
	req.key_len = keylen;
    if (hi_copy_from_user(req.src, aealg->param.rsa.src, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.d, aealg->param.rsa.d, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.e, aealg->param.rsa.e, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.n, aealg->param.rsa.n, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

//     /* e 参数校验,e < d */
//     if (hi_sec_pke_compare(req.d, req.e, keylen) <= 0) {
//         hi_free(data);
//         hi_pke_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
//         return HI_RET_INVALID_PARA;
//     }

//     /* RAS e 参数校验 , RSA 中e 是大于1的奇数 */
//     if (HI_RET_SUCC != hi_sec_pke_para_check(req.e, keylen,
//             HI_SEC_PKE_PARA_TYPE_ODD | HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1)) {
//         hi_free(data);
//         hi_pke_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
//         return HI_RET_INVALID_PARA;
//     }

	ret = hi_sec_rsa_pri_encrypt(&req);
    if (HI_RET_SUCC != ret) {
        hi_free(data);
        hi_pke_systrace(ret, 0, 0, 0, 0);
        return ret;
    }


    if (hi_copy_to_user(aealg->param.rsa.dst, req.dst, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    hi_free(data);
    hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
    return HI_RET_SUCC;
}


/* SEC RSA 公钥运算应用接口 */
static hi_int32 hi_sec_aealg_rsa_pub(struct hi_sec_aealg_s *aealg)
{
	hi_int32 ret;
	hi_uchar8 *data = HI_NULL;
	hi_uint32 keylen = aealg->param.rsa.key_len;
	struct hi_sec_rsa_req req;

    if (HI_SEC_PKE_RSA_1024BIT != keylen &&
        HI_SEC_PKE_RSA_2048BIT != keylen &&
        HI_SEC_PKE_RSA_3072BIT != keylen &&
        HI_SEC_PKE_RSA_4096BIT != keylen) {
        hi_pke_systrace(HI_RET_INVALID_PARA, keylen, 0, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    if (HI_NULL == aealg->param.rsa.src ||
        HI_NULL == aealg->param.rsa.e ||
        HI_NULL == aealg->param.rsa.d ||
        HI_NULL == aealg->param.rsa.n ||
        HI_NULL == aealg->param.rsa.dst) {
        hi_pke_systrace(HI_RET_NULLPTR, 0 , 0, 0, 0);
        return HI_RET_NULLPTR;
    }

    data = hi_malloc(HI_SEC_PKE_RSA_MAXLEN * 5);
    if (HI_NULL == data) {
        hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
        return HI_RET_MALLOC_FAIL;
    }

	req.src = data;
	req.e   = req.src + HI_SEC_PKE_RSA_MAXLEN;
	req.n   = req.e + HI_SEC_PKE_RSA_MAXLEN;
	req.dst = req.n + HI_SEC_PKE_RSA_MAXLEN;
	req.d   = req.dst + HI_SEC_PKE_RSA_MAXLEN;
	req.key_len = keylen;

    if (hi_copy_from_user(req.src, aealg->param.rsa.src, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.e, aealg->param.rsa.e, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.d, aealg->param.rsa.d, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.n, aealg->param.rsa.n, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

//     /* d 参数校验,e < d */
//     if (hi_sec_pke_compare(d, e, keylen) <= 0) {
//         hi_free(data);
//         hi_pke_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
//         return HI_RET_INVALID_PARA;
//     }

//     /* RAS d 参数校验 , RSA 中d 是大于1的奇数 */
//     if (HI_RET_SUCC != hi_sec_pke_para_check((hi_uchar8 *)d, keylen,
//             HI_SEC_PKE_PARA_TYPE_ODD | HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1)) {
//         hi_free(data);
//         hi_pke_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
//         return HI_RET_INVALID_PARA;
//     }

	ret = hi_sec_rsa_pub_encrypt(&req);
    if (HI_RET_SUCC != ret) {
        hi_free(data);
        hi_pke_systrace(ret, 0, 0, 0, 0);
        return ret;
    }

    if (hi_copy_to_user(aealg->param.rsa.dst, req.dst, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    hi_free(data);
    hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
    return HI_RET_SUCC;
}

/* SEC RSA 密钥产生应用接口 */
static hi_int32 hi_sec_aealg_rsa_keygen(struct hi_sec_aealg_s *aealg)
{
	hi_int32 ret;
	hi_uchar8 *data = HI_NULL;
	hi_uint32 keylen = aealg->param.rsa.key_len;
	struct hi_sec_rsa_req req;

    if (HI_SEC_PKE_RSA_1024BIT != keylen &&
        HI_SEC_PKE_RSA_2048BIT != keylen &&
        HI_SEC_PKE_RSA_3072BIT != keylen &&
        HI_SEC_PKE_RSA_4096BIT != keylen) {
        hi_pke_systrace(HI_RET_INVALID_PARA, keylen, 0, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    if (HI_NULL == aealg->param.rsa.e ||
        HI_NULL == aealg->param.rsa.d ||
        HI_NULL == aealg->param.rsa.n) {
        hi_pke_systrace(HI_RET_NULLPTR, 0 , 0, 0, 0);
        return HI_RET_NULLPTR;
    }

    data = hi_malloc(HI_SEC_PKE_RSA_MAXLEN * 3);
    if (HI_NULL == data) {
        hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
        return HI_RET_MALLOC_FAIL;
    }

	req.e = data;
	req.n = req.e + HI_SEC_PKE_RSA_MAXLEN;
	req.d = req.n + HI_SEC_PKE_RSA_MAXLEN;
	req.einput = aealg->param.rsa.einput;
	req.key_len = keylen;
	if (HI_DISABLE != aealg->param.rsa.einput) {
		if (hi_copy_from_user(req.e, aealg->param.rsa.e, keylen)) {
			hi_free(data);
			hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
			return HI_RET_FAIL;
		}
	}

    ret = hi_sec_rsa_keygen(&req);
    if (HI_RET_SUCC != ret) {
        hi_free(data);
        hi_pke_systrace(ret, 0, 0, 0, 0);
        return ret;
    }

    if (hi_copy_to_user(aealg->param.rsa.e, req.e, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_to_user(aealg->param.rsa.d, req.d, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_to_user(aealg->param.rsa.n, req.n, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    hi_free(data);
    hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
    return HI_RET_SUCC;
}

/* SEC DH 应用接口 */
static hi_int32 hi_sec_aealg_dh(struct hi_sec_aealg_s *aealg)
{
	hi_int32 ret;
	struct hi_sec_dh_req dh;
	hi_uchar8 *data = HI_NULL;
	hi_uint32 keylen = aealg->param.dh.key_len;

    if (HI_SEC_PKE_DH_768BIT != keylen  &&
        HI_SEC_PKE_DH_1024BIT != keylen &&
        HI_SEC_PKE_DH_1536BIT != keylen &&
        HI_SEC_PKE_DH_2048BIT != keylen &&
        HI_SEC_PKE_DH_3072BIT != keylen &&
        HI_SEC_PKE_DH_4096BIT != keylen) {
        hi_pke_systrace(HI_RET_INVALID_PARA, keylen, 0, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    if (HI_NULL == aealg->param.dh.g ||
        HI_NULL == aealg->param.dh.e ||
        HI_NULL == aealg->param.dh.n ||
        HI_NULL == aealg->param.dh.dst) {
        hi_pke_systrace(HI_RET_NULLPTR, 0 , 0, 0, 0);
        return HI_RET_NULLPTR;
    }

    data = hi_malloc(HI_SEC_PKE_DH_MAXLEN * 4);
    if (HI_NULL == data) {
        hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
        return HI_RET_MALLOC_FAIL;
    }

	dh.g = data;
	dh.e = data + HI_SEC_PKE_DH_MAXLEN;
	dh.n = data + HI_SEC_PKE_DH_MAXLEN * 2;
	dh.dst = data + HI_SEC_PKE_DH_MAXLEN * 3;
	dh.key_len = aealg->param.dh.key_len;

    if (hi_copy_from_user(dh.g, aealg->param.dh.g, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(dh.e, aealg->param.dh.e, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(dh.n, aealg->param.dh.n, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    ret = hi_sec_dh_keygen(&dh);
    if (HI_RET_SUCC != ret) {
        hi_free(data);
        hi_pke_systrace(ret, 0, 0, 0, 0);
        return ret;
    }

    if (hi_copy_to_user(aealg->param.dh.dst, dh.dst, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    hi_free(data);
    hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
    return HI_RET_SUCC;
}

/* SEC ECDSA 签名应用接口 */
static hi_int32 hi_sec_aealg_ecdsa_sign(struct hi_sec_aealg_s *aealg)
{
	hi_int32 ret;
	hi_uchar8 *data = HI_NULL;
	hi_uint32 keylen = aealg->param.ecdsa.key_len;
	struct hi_sec_ecdsa_req req;

    if (HI_SEC_PKE_ECDSA_192BIT != keylen &&
        HI_SEC_PKE_ECDSA_224BIT != keylen &&
        HI_SEC_PKE_ECDSA_256BIT != keylen &&
        HI_SEC_PKE_ECDSA_384BIT != keylen &&
        HI_SEC_PKE_ECDSA_521BIT != keylen) {
        hi_pke_systrace(HI_RET_INVALID_PARA, keylen, 0, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    if (HI_NULL == aealg->param.ecdsa.m ||
        HI_NULL == aealg->param.ecdsa.d ||
        HI_NULL == aealg->param.ecdsa.sx ||
        HI_NULL == aealg->param.ecdsa.sy) {
        hi_pke_systrace(HI_RET_NULLPTR, 0 , 0, 0, 0);
        return HI_RET_NULLPTR;
    }

    data = hi_malloc(HI_SEC_PKE_ECDSA_MAXLEN * 4);
    if (HI_NULL == data) {
        hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
        return HI_RET_MALLOC_FAIL;
    }

	req.m = data;
	req.d = req.m + HI_SEC_PKE_ECDSA_MAXLEN;
	req.sx = req.d + HI_SEC_PKE_ECDSA_MAXLEN;
	req.sy = req.sx + HI_SEC_PKE_ECDSA_MAXLEN;
	req.key_len = keylen;
    if (hi_copy_from_user(req.m, aealg->param.ecdsa.m, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.d, aealg->param.ecdsa.d, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    ret = hi_sec_ecdsa_sign(&req);
    if (HI_RET_SUCC != ret) {
        hi_free(data);
        hi_pke_systrace(ret, 0, 0, 0, 0);
        return ret;
    }

    if (hi_copy_to_user(aealg->param.ecdsa.sx, req.sx, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_to_user(aealg->param.ecdsa.sy, req.sy, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    hi_free(data);
    hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
    return HI_RET_SUCC;
}

/* SEC ECDSA 验签应用接口 */
static hi_int32 hi_sec_aealg_ecdsa_verif(struct hi_sec_aealg_s *aealg)
{
	hi_int32 ret;
	hi_uchar8 *data = HI_NULL;
	hi_uint32 keylen = aealg->param.ecdsa.key_len;
	struct hi_sec_ecdsa_req req;

    if (HI_SEC_PKE_ECDSA_192BIT != keylen &&
        HI_SEC_PKE_ECDSA_224BIT != keylen &&
        HI_SEC_PKE_ECDSA_256BIT != keylen &&
        HI_SEC_PKE_ECDSA_384BIT != keylen &&
        HI_SEC_PKE_ECDSA_521BIT != keylen) {
        hi_pke_systrace(HI_RET_INVALID_PARA, keylen, 0, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    if (HI_NULL == aealg->param.ecdsa.m ||
        HI_NULL == aealg->param.ecdsa.qx ||
        HI_NULL == aealg->param.ecdsa.qy ||
        HI_NULL == aealg->param.ecdsa.sx ||
        HI_NULL == aealg->param.ecdsa.sy) {
        hi_pke_systrace(HI_RET_NULLPTR, 0 , 0, 0, 0);
        return HI_RET_NULLPTR;
    }

    data = hi_malloc(HI_SEC_PKE_ECDSA_MAXLEN * 5);
    if (HI_NULL == data) {
        hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
        return HI_RET_MALLOC_FAIL;
    }

	req.m = data;
	req.qx = req.m + HI_SEC_PKE_ECDSA_MAXLEN;
	req.qy = req.qx + HI_SEC_PKE_ECDSA_MAXLEN;
	req.sx = req.qy + HI_SEC_PKE_ECDSA_MAXLEN;
	req.sy = req.sx + HI_SEC_PKE_ECDSA_MAXLEN;
	req.key_len = keylen;
    if (hi_copy_from_user(req.m, aealg->param.ecdsa.m, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.qx, aealg->param.ecdsa.qx, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.qy, aealg->param.ecdsa.qy, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.sx, aealg->param.ecdsa.sx, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.sy, aealg->param.ecdsa.sy, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

	ret = hi_sec_ecdsa_verify(&req);
    if (HI_RET_SUCC != ret) {
        hi_free(data);
        hi_pke_systrace(ret, 0, 0, 0, 0);
        return ret;
    }

    hi_free(data);
    hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
    return HI_RET_SUCC;
}

static hi_int32 hi_sec_aealg_ecdsa_keygen(struct hi_sec_aealg_s *aealg)
{
	hi_int32 ret;
	hi_uchar8 *data = HI_NULL;
	hi_uint32 keylen = aealg->param.ecdsa.key_len;
	struct hi_sec_ecdsa_req req;

    if (HI_SEC_PKE_ECDSA_192BIT != keylen &&
        HI_SEC_PKE_ECDSA_224BIT != keylen &&
        HI_SEC_PKE_ECDSA_256BIT != keylen &&
        HI_SEC_PKE_ECDSA_384BIT != keylen &&
        HI_SEC_PKE_ECDSA_521BIT != keylen) {
        hi_pke_systrace(HI_RET_INVALID_PARA, keylen, 0, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    if (HI_NULL == aealg->param.ecdsa.d ||
        HI_NULL == aealg->param.ecdsa.qx ||
        HI_NULL == aealg->param.ecdsa.qy) {
        hi_pke_systrace(HI_RET_NULLPTR, 0 , 0, 0, 0);
        return HI_RET_NULLPTR;
    }

    data = hi_malloc(HI_SEC_PKE_ECDSA_MAXLEN * 3);
    if (HI_NULL == data) {
        hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
        return HI_RET_MALLOC_FAIL;
    }

	req.d = data;
	req.qx = req.d + HI_SEC_PKE_ECDSA_MAXLEN;
	req.qy = req.qx + HI_SEC_PKE_ECDSA_MAXLEN;
	req.key_len = keylen;
	ret = hi_sec_ecdsa_keygen(&req);
    if (HI_RET_SUCC != ret) {
        hi_free(data);
        hi_pke_systrace(ret, 0, 0, 0, 0);
        return ret;
    }

    if (hi_copy_to_user(aealg->param.ecdsa.d, req.d, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_to_user(aealg->param.ecdsa.qx, req.qx, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_to_user(aealg->param.ecdsa.qy, req.qy, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    hi_free(data);
    data = HI_NULL;
    hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
    return HI_RET_SUCC;
}

static hi_int32 hi_sec_aealg_ecdsa_keychk(struct hi_sec_aealg_s *aealg)
{
	hi_int32 ret;
	hi_uchar8 *data = HI_NULL;
	hi_uint32 keylen = aealg->param.ecdsa.key_len;
	struct hi_sec_ecdsa_req req;

    if (HI_SEC_PKE_ECDSA_192BIT != keylen &&
        HI_SEC_PKE_ECDSA_224BIT != keylen &&
        HI_SEC_PKE_ECDSA_256BIT != keylen &&
        HI_SEC_PKE_ECDSA_384BIT != keylen &&
        HI_SEC_PKE_ECDSA_521BIT != keylen) {
        hi_pke_systrace(HI_RET_INVALID_PARA, keylen, 0, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    if (HI_NULL == aealg->param.ecdsa.qx
        || HI_NULL == aealg->param.ecdsa.qy) {
        hi_pke_systrace(HI_RET_NULLPTR, 0 , 0, 0, 0);
        return HI_RET_NULLPTR;
    }

    data = hi_malloc(HI_SEC_PKE_ECDSA_MAXLEN * 2);
    if (HI_NULL == data) {
        hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
        return HI_RET_MALLOC_FAIL;
    }

	req.qx = data;
	req.qy = req.qx + HI_SEC_PKE_ECDSA_MAXLEN;
	req.key_len = keylen;
    if (hi_copy_from_user(req.qx, aealg->param.ecdsa.qx, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

    if (hi_copy_from_user(req.qy, aealg->param.ecdsa.qy, keylen)) {
        hi_free(data);
        hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
        return HI_RET_FAIL;
    }

	ret = hi_sec_ecdsa_keychk(&req);
    if (HI_RET_SUCC != ret) {
        hi_free(data);
        hi_pke_systrace(ret, 0, 0, 0, 0);
        return ret;
    }

    hi_free(data);
    hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
    return HI_RET_SUCC;
}

/* SEC非对称算法接口 */
hi_int32 hi_sec_aealg(struct hi_sec_aealg_s *aealg)
{
    hi_int32 ret;
    hi_sec_aealg_func pfc_func;

    if (HI_NULL == aealg) {
        hi_pke_systrace(HI_RET_NULLPTR, aealg, 0, 0, 0);
        return HI_RET_NULLPTR;
    }

    if (aealg->alg > HI_SEC_AEALG_ECDSA ||
        aealg->func > HI_SEC_AEALG_FUNC_KEYCHK) {
        hi_pke_systrace(HI_RET_INVALID_PARA, aealg->alg, aealg->func, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    ///* 上锁 */
    //if (hi_down_interruptible(&g_sec_pke.sem)) {
    //    hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
    //    return HI_RET_FAIL;
    //}

    pfc_func = g_apfc_aealg[aealg->alg][aealg->func];

    if (HI_NULL != pfc_func) {
        ret = pfc_func(aealg);
    } else {
        ///* 解锁 */
        //hi_up(&g_sec_pke.sem);

        hi_pke_systrace(HI_RET_INVALID_PARA, aealg->alg, aealg->func, 0, 0);
        return HI_RET_INVALID_PARA;
    }

    ///* 解锁 */
    //hi_up(&g_sec_pke.sem);

    if (ret != HI_RET_SUCC) {
        hi_pke_systrace(ret, 0, 0, 0, 0);
        return ret;
    }

    hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
    return HI_RET_SUCC;
}
EXPORT_SYMBOL(hi_sec_aealg);

/* 执行非对称算法运算 */
hi_int32 hi_dfx_sec_aealg(struct hi_sec_aealg_s *aealg)
{
	struct timeval time_start;
	struct timeval time_end;
	hi_uint32 index;
	hi_int32 ret;

	do_gettimeofday(&time_start);

	for (index = 0; index < g_dfx_sec_cmd.n; index++) {
		ret = hi_sec_aealg(aealg);
		if (ret != HI_RET_SUCC) {
			return ret;
		}
	}

	do_gettimeofday(&time_end);
	hi_dfx_sec_time(&time_start, &time_end);
	hi_printk("aealg[%d] func[%d] [%d]times: sec[%d] usec[%d]\n",
		  aealg->alg, aealg->func, g_dfx_sec_cmd.n,
		  g_dfx_sec_cmd.time_s, g_dfx_sec_cmd.time_us);

	return HI_RET_SUCC;
}
HI_EXPORT_IPC11(hi_dfx_sec_aealg);

hi_int32 hi_trng_cmd_get(hi_void *arg)
{
	struct hi_sec_trng *rng = (struct hi_sec_trng *)arg;
	return hi_sec_trng_get(rng);
}
HI_EXPORT_IPC11(hi_trng_cmd_get);

hi_uint32 hi_kdf_to_dev_cmd(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen)
{
    struct hi_sec_pbkdf2 *to_devpara = (struct hi_sec_pbkdf2 *)data;
    return hi_kdf_to_dev(to_devpara);
}
HI_EXPORT_IPC30(hi_kdf_to_dev_cmd);

hi_uint32 hi_kdf_to_store_cmd(hi_void *data, hi_uint32 inlen, hi_uint32 *outlen)
{
    struct hi_sec_kdf_internal *to_store = (struct hi_sec_kdf_internal *)data;
    return hi_kdf_to_store(to_store);
}
HI_EXPORT_IPC30(hi_kdf_to_store_cmd);