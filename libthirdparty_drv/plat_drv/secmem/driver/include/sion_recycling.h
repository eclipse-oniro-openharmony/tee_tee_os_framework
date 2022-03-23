/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: ion recycle
 * Author: jianfujian
 * Create: 2019-11-04
 */

#ifndef __SION_RECYCLING_H__
#define __SION_RECYCLING_H__

#include "sec_common.h"
#include "tee_defines.h"
#include "dynion.h"

#ifdef CONFIG_HISI_SION_RECYCLE
extern int sion_record_sglist(const struct sglist *sglist,
				const TEE_UUID *cur_uuid,
				unsigned int protect_id);
extern int sion_record_remove(const struct sglist *sglist,
				const TEE_UUID *cur_uuid);
extern void sion_recycle_init(void);
#else
static inline int sion_record_sglist(const struct sglist *sglist,
				const TEE_UUID *cur_uuid,
				unsigned int protect_id)
{
	(void)sglist;
	(void)cur_uuid;
	(void)protect_id;
	return 0;
}

static inline int sion_record_remove(const struct sglist *sglist,
				const TEE_UUID *cur_uuid)
{
	(void)sglist;
	(void)cur_uuid;
	return 0;
}

static inline void sion_recycle_init(void)
{
}
#endif

#endif
