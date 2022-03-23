/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Teeos to atf: eSE transmit data.
 * Create: 2019/7/30
 */

#include "ese_data_handle.h"
#include <errno.h>
#include <drv_mem.h> // sre_mmap
#include <drv_module.h>
#include <drv_cache_flush.h> // v7_dma_flush_range
#include "mem_page_ops.h"
#include "ipc_a.h"
#include "ipc_call.h"
#include "hisee.h"
#include "se_hal.h"
#include "pthread.h"
#include "tee_log.h" /* uart_printf_func */
#include "securec.h"

#ifdef SE_USE_ESE_I2C
#include "bl31_platform_memory_def.h"

#define MAGIC_DATA              0xdeadbeaf
#define SZ_4K                   0x00001000
#define SIZE                    (2 * sizeof(int))
#define ESE_FAILURE              -1

#ifndef TEE_ESE_TRANSMIT
#define TEE_ESE_TRANSMIT        0xfffA
#endif
#ifndef TEE_ESE_READ
#define TEE_ESE_READ            0xfffB
#endif

static pthread_mutex_t g_tee2atf_lock;

#endif /* end of SE_USE_ESE_I2C */

extern int __ipc_smc_switch(unsigned int irq);

/*
 * @brief    :transmit tee->atf->i2c->ese
 * @param[in]:data: address to transmit
 * @param[in]:data_size: support max size is 4K bytes
 * @return   :0x00 for okay
 *            0x01 for param error
 *            0x02 for transmit error
 *            0x09 ese not exist
 */
int ese_transmit_data(unsigned char *data, unsigned int data_size)
{
#ifndef SE_USE_ESE_I2C
	(void)data;
	(void)data_size;
	tloge("not support ese\n");
	return 0;
#else
	int ret;
	unsigned int map_dst_addr = 0;
	unsigned int magic_data = MAGIC_DATA;

	/*
	 * the data_size include the len and the magic, so it
	 * should minus 2*sizeof(int).
	 */
	if (!data_size || !data || data_size > SZ_4K - SIZE) {
		tloge("%s: Invalid input parameter!\n", __func__);
		return ESE_TRS_PARAM_ERR;
	}

	ret = pthread_mutex_lock(&g_tee2atf_lock);
	if (ret != SRE_OK) {
		tloge("%s:Wait g_tee2atf_lock failed: %x!\n", __func__, ret);
		return ret;
	}
	/* map default: cacheable */
	if (sre_mmap(HISI_ATF_TEE_SHMEM_ADDR, HISI_ATF_TEE_SHMEM_SIZE,
		     &map_dst_addr, secure, cache)) {
		tloge("%s: data buffer map failed!\n", __func__);
		ret = ESE_TRS_DATA_ERR;
		goto err;
	}

	/*
	 *      4bytes            data_size             magic
	 *  |--  len   --||--     real data    --||-- 0xdeadbeaf --|
	 */
	ret = memcpy_s((void *)(uintptr_t)(map_dst_addr), sizeof(unsigned int),
		       (void *)&data_size, sizeof(data_size));
	ret += memcpy_s((void *)(uintptr_t)(map_dst_addr + sizeof(int)),
			HISI_ATF_TEE_SHMEM_SIZE - SIZE, (void *)data, data_size);
	ret += memcpy_s((void *)(uintptr_t)(map_dst_addr + data_size + sizeof(int)),
			HISI_ATF_TEE_SHMEM_SIZE - data_size - sizeof(int),
			(void *)&magic_data, sizeof(magic_data));
	if (ret != EOK) {
		tloge("%s memcpy data, error ret %d\n", __func__, ret);
		(void)sre_unmap(map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE);
		goto err;
	}

	/*
	 * flash cache for different cpu mapping, teeos cached, atf none-cached
	 */
	v7_dma_flush_range(map_dst_addr, map_dst_addr + data_size);

	/* just return it, it's the same design of return-value in atf */
	ret = __ipc_smc_switch(TEE_ESE_TRANSMIT);
	if (ret != 0)
		tloge("%s TRANSMIT! error ret %d\n", __func__, ret);

	ret = memset_s((void *)(uintptr_t)map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE, 0, data_size + SIZE);
	if (ret != EOK) {
		tloge("%s clear data, error ret %d\n", __func__, ret);
		(void)sre_unmap(map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE);
		goto err;
	}
	(void)sre_unmap(map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE);

err:
	if (pthread_mutex_unlock(&g_tee2atf_lock) != SRE_OK) {
		ret = ESE_FAILURE;
		tloge("%s:Release g_tee2atf_lock failed: %x!\n", __func__, ret);
	}
	return ret;
#endif
}

/*
 * @brief    :read data from ese;ese->i2c->atf->tee
 *            the same story as ese_transmit_data
 * @param[in]:data, read aid data
 * @param[in]:data_size, read data size
 * @return   :0x09 for ese not support, max size is 4k bytes
 */
int ese_read_data(unsigned char *data, unsigned int data_size)
{
#ifndef SE_USE_ESE_I2C
	(void)data;
	(void)data_size;
	tloge("not support ese\n");
	return 0;
#else
	int ret;
	unsigned int map_dst_addr = 0;

	if (!data_size || !data || data_size > HISI_ATF_TEE_SHMEM_SIZE - SIZE) {
		tloge("%s: Invalid input parameter!\n", __func__);
		return ESE_TRS_PARAM_ERR;
	}

	ret = pthread_mutex_lock(&g_tee2atf_lock);
	if (ret != SRE_OK) {
		tloge("%s:Wait g_tee2atf_lock failed: %x!\n", __func__, ret);
		return ret;
	}
	if (sre_mmap(HISI_ATF_TEE_SHMEM_ADDR, HISI_ATF_TEE_SHMEM_SIZE,
		     &map_dst_addr, secure, cache)) {
		tloge("%s: data buffer map failed!\n", __func__);
		ret = ESE_TRS_DATA_ERR;
		goto err;
	}

	ret = memcpy_s((void *)(uintptr_t)(map_dst_addr), sizeof(unsigned int),
		       (void *)&data_size, sizeof(data_size));
	if (ret != EOK) {
		tloge("%s memcpy to dst_addr, error ret %d\n", __func__, ret);
		(void)sre_unmap(map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE);
		goto err;
	}
	v7_dma_flush_range(map_dst_addr, map_dst_addr + data_size);

	/* just return it, it's the same design of return-value in atf */
	ret = __ipc_smc_switch(TEE_ESE_READ);
	if (ret != 0)
		tloge("%s READ! error ret %d\n", __func__, ret);

	ret = memcpy_s((void *)data, HISI_ATF_TEE_SHMEM_SIZE, (void *)(uintptr_t)map_dst_addr, data_size);
	if (ret != EOK) {
		tloge("%s memcpy map address, error ret %d\n", __func__, ret);
		(void)sre_unmap(map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE);
		goto err;
	}

	(void)sre_unmap(map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE);

err:
	if (pthread_mutex_unlock(&g_tee2atf_lock) != SRE_OK) {
		ret = ESE_FAILURE;
		tloge("%s:Release g_tee2atf_lock failed: %x!\n", __func__, ret);
	}
	return ret;
#endif
}

/*
 * @brief      : ese_tee_init : initialize ese_tee data module, mainly for g_tee2atf_lock.
 * @return     : OK: initialize successfully, others: initialize failed.
 */
static int ese_tee_init(void)
{
#ifndef SE_USE_ESE_I2C
	return 0;
#else
	int ret;

	ret = pthread_mutex_init(&g_tee2atf_lock, NULL);
	if (ret != SRE_OK) {
		uart_printf_func("%s:Create g_tee2atf_lock mutex failed! ret = %x\n", __func__, ret);
		return ret;
	}
	return 0;
#endif
}

/* declare ese_tee data module */
DECLARE_TC_DRV(
	ese_tee_driver,     /* name */
	0,                  /* reserved1 */
	0,                  /* reserved2 */
	0,                  /* reserved3 */
	TC_DRV_MODULE_INIT, /* priority */
	ese_tee_init,       /* init */
	NULL,               /* handle */
	NULL,               /* syscall */
	NULL,               /* suspend */
	NULL                /* resume */
);

