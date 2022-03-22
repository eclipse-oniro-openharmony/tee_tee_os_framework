/**
 * @file   : common_symm.h
 * @brief  : common data provided for drv.c, hal.c, reg.c and external
 * @par    : Copyright (c) 2017-2019, HUAWEI Technology Co., Ltd.
 * @date   : 2018/01/09
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __COMMON_SYMM_H__
#define __COMMON_SYMM_H__
#include <common_km.h>
#include <common_sce.h>

typedef enum {
	SYMM_CHANNEL_SMMU_SMMU     = 0, /* read channel is SMMU, write channel is SMMU */
	SYMM_CHANNEL_SMMU_DDRENC   = 1, /* read channel is SMMU, write channel is DDRENC */
	SYMM_CHANNEL_DDRENC_SMMU   = 2, /* read channel is DDRENC, write channel is SMMU */
	SYMM_CHANNEL_DDRENC_DDRENC = 3, /* read channel is DDRENC, write channel is DDRENC */
	SYMM_CHANNEL_MAX
} symm_ddr_channel_e;

typedef enum {
	SYMM_SCE1 = 0,
	SYMM_SCE2 = 1,
	SYMM_SCE_MAX,
	SYMM_SCE_INVALID = SYMM_SCE_MAX
} symm_sce_ip_e;

#define SYMM_BLKLEN_HASH_MAX                  SYMM_BLKLEN_HASH_SHA512
#define SYMM_OUTLEN_HASH_MAX                  SYMM_OUTLEN_SHA512

#define SYMM_ALG_IS_CRYPTO(alg) ((alg) <= SYMM_ALGORITHM_CRYPTO)
#define SYMM_ALG_IS_HASH(alg)   ((SYMM_ALGORITHM_HASH_START <= (alg)) && \
									((alg) <= SYMM_ALGORITHM_HASH_END))

#endif /* end of __COMMON_SYMM_H__ */
