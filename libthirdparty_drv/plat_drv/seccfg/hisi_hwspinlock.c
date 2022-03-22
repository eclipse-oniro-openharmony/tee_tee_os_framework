/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: secure os hwspinlock module
 * CPU ID for master running hisi kernel.
 * Hswpinlocks should only be used to synchonise operations
 * between the Cortex A_x core and the other CPUs.  Hence
 * forcing the masterID to a preset value.
 *
 * Author: hisilicon
 * Create: 2018-05-21
 */
#include "hwspinlock.h"
#include "sre_log.h"
#include "soc_acpu_baseaddr_interface.h"

#define SECURE_OS_ID 0x07
#define MASTER_ID SECURE_OS_ID
#define LOCK_CMD ((MASTER_ID << 1) | 0x01)
#define UNLOCK_CMD LOCK_CMD
#define ID_MASK 0x0f

#define writel(val, addr) \
	((*(volatile unsigned int *)((unsigned long)(addr))) = (val))
#define readl(addr) \
	(*(volatile unsigned int *)((unsigned long)(addr)))

#define HWSPINLOCK_LOCK(n) \
	(SOC_ACPU_PCTRL_BASE_ADDR + (((n) / 4 + 1) * 0x400) + \
		(((n) % 4) * 0x0C))
#define HWSPINLOCK_UNLOCK(n) \
	(SOC_ACPU_PCTRL_BASE_ADDR + (((n) / 4 + 1) * 0x400 + (0x4)) + \
		(((n) % 4) * 0x0C))
#define HWSPINLOCK_STATUS(n) \
	(SOC_ACPU_PCTRL_BASE_ADDR + (((n) / 4 + 1) * 0x400 + (0x8)) + \
		(((n) % 4) * 0x0C))

#define NUM_A_GROUP 8
#define GROUPS 8
#define ID_MAX (GROUPS * NUM_A_GROUP)
#define REG_NUM_SINGLE 4

#define GET_ID_INFO(id, grp, num) \
do {\
	(grp) = (id) / NUM_A_GROUP;\
	(num) = (id) % NUM_A_GROUP;\
} while (0)

int hwspin_trylock(int id)
{
	unsigned int reg, grp, num;

	if (id >= ID_MAX) {
		tloge("LockEnIdErr%d\n", id);
		return HS_EID;
	}

	GET_ID_INFO(id, grp, num);

	writel((LOCK_CMD << (num * REG_NUM_SINGLE)), HWSPINLOCK_LOCK(grp));
	reg = ((readl(HWSPINLOCK_STATUS(grp))) >> (num * REG_NUM_SINGLE)) &
		ID_MASK;

	return (reg == LOCK_CMD) ? HS_OK : HS_EFAIL;
}

int hwspin_unlock(int id)
{
	unsigned int grp, num;

	if (id >= ID_MAX) {
		tloge("LockDisIdErr%d\n", id);
		return HS_EID;
	}

	GET_ID_INFO(id, grp, num);

	writel((UNLOCK_CMD << (num * REG_NUM_SINGLE)), HWSPINLOCK_UNLOCK(grp));

	return HS_OK;
}

int hwspin_lock_timeout(int id, unsigned int to)
{
	int ret;
	unsigned int time_to = to;

	if (id >= ID_MAX) {
		tloge("LockTryIdErr%d\n", id);
		return HS_EID;
	}

	if (time_to > WAITTIME_MAX) {
		tloge("LockTimeOverMax%u\n", time_to);
		time_to = WAITTIME_MAX;
	}

	for (;;) {
		/* Try to take the hwspinlock */
		ret = hwspin_trylock(id);
		if (!time_to || !ret)
			break;

		/*
		 * The lock is already taken, let's check if the user wants
		 * us to try again
		 */
		time_to--;
	}

	return ret;
}
