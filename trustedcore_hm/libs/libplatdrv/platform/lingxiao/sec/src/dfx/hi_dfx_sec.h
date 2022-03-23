/******************************************************************************

          版权所有 (C), 2008-2018, 海思半导体有限公司

******************************************************************************
  文件名称: hi_dfx_sec.c
  功能描述: 安全模块DFX功能头文件
  版本描述: V1.0

  创建日期: D2017_10_27
  创建作者: ouweiquan 00302765

  修改记录:
            生成初稿.
******************************************************************************/

#ifndef __HI_DFX_SEC_H__
#define __HI_DFX_SEC_H__

#include "hi_sec_pke.h"
#include "hi_sec_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

struct hi_dfx_sec_cmd_s {
	hi_uint32 n;        //运算次数N
	hi_uint32 time_s;   //N次运算花费的秒时间
	hi_uint32 time_us;  //N次运算花费的微秒时间
};

struct hi_sec_dfx_enc_s {
	hi_uchar8 *src;
	hi_uchar8 *dst;
	hi_uchar8 *key;
	hi_uchar8 *iv;
	hi_uint32 keylen;
	hi_uint32 cryptlen;
	hi_uint32 keymode;
};

struct hi_sec_dfx_auth_s {
	hi_uchar8 *assoc;
	hi_uchar8 *hash;
	hi_uchar8 *akey;
	hi_uint32 assoclen;
	hi_uint32 akeylen;
};

struct hi_sec_dfx_authenc_s {
	hi_uchar8 *src;
	hi_uchar8 *dst;
	hi_uchar8 *assoc;
	hi_uchar8 *key;
	hi_uchar8 *akey;
	hi_uchar8 *iv;
	hi_uint32 cryptlen;
	hi_uint32 assoclen;
	hi_uint32 keylen;
	hi_uint32 akeylen;
	hi_uint32 authsize;
	hi_uint32 ivsize;
	hi_uint32 keymode;
};

struct hi_sec_dfx_alg_cmd_s {
	hi_uint32 cipher;
	hi_uint32 enc;
	hi_uint32 hash;
	union {
		struct hi_sec_dfx_enc_s enc;
		struct hi_sec_dfx_auth_s auth;
		struct hi_sec_dfx_authenc_s authenc;
	} param;
};

struct hi_sec_aealg_s {
	enum hi_sec_aealg_e alg;
	enum hi_sec_aealg_func_e func;
	union {
		struct hi_sec_rsa_req rsa;
		struct hi_sec_dh_req dh;
		struct hi_sec_ecdsa_req ecdsa;
	} param;
};

struct hi_sec_pke_dfx_s
{
    hi_uint32 ui_pointmulti_dfx;
    hi_uchar8 auc_pointmulti_k[HI_SEC_PKE_ECDSA_521BIT];
};

hi_int32 hi_dfx_sec_aealg(struct hi_sec_aealg_s *aealg);
hi_int32 hi_dfx_sec_cmd_n_set(struct hi_dfx_sec_cmd_s *pst_cmd);
hi_int32 hi_dfx_sec_cmd_n_get(struct hi_dfx_sec_cmd_s *pst_cmd);
hi_int32 hi_dfx_sec_aealg_pointmultik_set(struct hi_sec_pke_dfx_s *pst_dfx);
hi_int32 hi_dfx_sec_aealg_pointmultik_get(hi_uint32 *pui_enable);
hi_int32 hi_dfx_sec_aealg_sta_get(struct hi_sec_pke_sta_s *pst_sta);
hi_int32 hi_dfx_sec_alg_attr_set(struct hi_sec_attr_s *pst_attr);
hi_int32 hi_dfx_sec_alg_attr_get(struct hi_sec_attr_s *pst_attr);
hi_int32 hi_dfx_sec_alg_cnt_get(struct hi_sec_cnt_s *pst_cnt);
hi_int32 hi_dfx_sec_alg_sta_get(struct hi_sec_sta_s *pst_sta);
hi_int32 hi_dfx_sec_drv_qidmap_set(struct hi_sec_drv_qid_map_s *pst_map);

hi_int32 hi_dfx_sec_alg_cmd(struct hi_sec_dfx_alg_cmd_s *cmd);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif /* __HI_DFX_SEC_H__ */

