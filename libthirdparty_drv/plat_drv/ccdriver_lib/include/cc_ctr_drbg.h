/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cc engine: ctr-drbg defination.
 * Create: 2020/02/20
 */

#ifndef _CC_CTR_DRBG_H_
#define _CC_CTR_DRBG_H_

#include "cc_rnd.h"

/* must same define as cavpca */
#define MAX_ENTROPY_LEN     128
#define MAX_NONCE_LEN       64
#define MAX_PERSONALSTR_LEN 256
#define MAX_ENTROPYINPR_LEN 128
#define MAX_ADDINPUT_LEN    256

/* the following is same with cc_ctr_drbg.h in dx. so use camel style*/
struct cc_drbg_data {
	uint32_t aesUseDf;   /* unused in ta. */
	uint32_t preResist;  /* unused in ta. */
	uint32_t enCountAdd; /* cnt of AdditionalInput <= 2. unused in ta. */
	uint32_t enCountEnt; /* cnt of EntropyInputPR <= 2. unused in ta. */
	uint32_t count;      /* unused in ta. */
	uint8_t  pEntropy[MAX_ENTROPY_LEN];
	uint32_t entropySize;
	uint8_t  pNonce[MAX_NONCE_LEN];
	uint32_t nonceSize;
	uint8_t  pPersonalStr[MAX_PERSONALSTR_LEN];
	uint32_t personalStrSize;
	uint8_t  pEntropyInPR1[MAX_ENTROPYINPR_LEN];
	uint32_t entropyInPR1Size;
	uint8_t  pEntropyInPR2[MAX_ENTROPYINPR_LEN];
	uint32_t entropyInPR2Size;
	uint8_t  pAddInput1[MAX_ADDINPUT_LEN];
	uint32_t addInput1Size;
	uint8_t  pAddInput2[MAX_ADDINPUT_LEN];
	uint32_t addInput2Size;
};

#ifdef CC_SUPPORT_FIPS
uint32_t do_prng_test(
	CCRndContext_t      *pRndContext,
	CCPrngFipsKatCtx_t  *pPrngCtx,
	struct cc_drbg_data *prngTestVector);
#else
static inline uint32_t do_prng_test(
	CCRndContext_t      *pRndContext,
	CCPrngFipsKatCtx_t  *pPrngCtx,
	struct cc_drbg_data *prngTestVector)
{
	(void)pRndContext;
	(void)pPrngCtx;
	(void)prngTestVector;

	return 0;
}
#endif

/*
 * the following are customized as needed.
 */
/* this struct is defined for user just like mdpp ta */
struct dx_ctr_drbg {
	CCRndContext_t      pRndContext;
	CCPrngFipsKatCtx_t  pPrngCtx;
	struct cc_drbg_data pPrngTestData;
};

#ifndef CC_ENGINE_ENABLE
/* for miami(cc63), cc_adapt.c haven't been compiled. so can define this macro */
static inline uint32_t crys_do_drbg_test(
	struct cc_drbg_data *drbg_data_addr, uint32_t drbg_data_size,
	CCPrngFipsKatCtx_t *kat_ctx_addr, uint32_t kat_ctx_size,
	CCRndContext_t *rnd_context_addr, uint32_t rnd_context_size)
{
	(void)drbg_data_addr;
	(void)drbg_data_size;
	(void)kat_ctx_addr;
	(void)kat_ctx_size;
	(void)rnd_context_addr;
	(void)rnd_context_size;

	return 0;
}
#else
uint32_t crys_do_drbg_test(
	struct cc_drbg_data *drbg_data_addr, uint32_t drbg_data_size,
	CCPrngFipsKatCtx_t *kat_ctx_addr, uint32_t kat_ctx_size,
	CCRndContext_t *rnd_context_addr, uint32_t rnd_context_size);
#endif

#endif /* _CC_CTR_DRBG_H_ */

