/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2019. All rights reserved.
 * Description: secboot TA
 * Create: 2013/5/16
 */

#ifndef __HISI_SECLOCK_H__
#define __HISI_SECLOCK_H__

#include <sre_typedef.h>

typedef enum SECBOOT_LOCKSTATE_TAG {
	SECBOOT_LSTATE_LOCKED = 0,
	SECBOOT_LSTATE_UNLOCKED = 1,
	SECBOOT_LSTATE_RELOCKED = 2,
} SECBOOT_LOCKSTATE;

SECBOOT_LOCKSTATE hisi_secboot_get_lockstate(void);
UINT32 hisi_secboot_set_lockstate(SECBOOT_LOCKSTATE lockstate,
				  const char *passwordptr);

#endif
