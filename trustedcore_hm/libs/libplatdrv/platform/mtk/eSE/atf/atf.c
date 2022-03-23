#include "atf.h"
#include <errno.h>
#include <sre_sys.h>
#include "sre_task.h"
#include "pthread.h"
#include "tee_log.h"
#include "securec.h"
#include "drv_mem.h"
#include "spi.h"

#define MAGIC_DATA              0xdeadbeaf
#define SZ_4K                   0x00001000
#define SIZE                    (2 * sizeof(int))
#define ESE_FAILURE              -1

#ifndef TEE_ESE_TRANSMIT
#define TEE_ESE_TRANSMIT        0xfffA
#endif
#define HISI_ATF_TEE_SHMEM_ADDR (0x4CFCE000)
#define HISI_ATF_TEE_SHMEM_SIZE (0x1000)

#define HISI_SMC_FID 0x82000055

extern int __smc_switch_to_atf(uint32_t smc_fid, void *info);
extern void __dma_flush_range(unsigned long start, unsigned long end);
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
	int ret;
	int i = 0;
	unsigned int map_dst_addr = 0;
	unsigned int magic_data = MAGIC_DATA;
	struct hieps_smc_atf ese_smc_data = {
 		.x1 = TEE_ESE_TRANSMIT,
 		.x2 = 0,
 		.x3 = 0,
 		.x4 = 0,
 	};
	tloge("%s: ese_transmit_data enter!\n", __func__);

	/*
	 * the data_size include the len and the magic, so it
	 * should minus 2*sizeof(int).
	 */
	if (!data_size || !data || data_size > SZ_4K - SIZE) {
		tloge("%s: Invalid input parameter!\n", __func__);
		return ESE_TRS_PARAM_ERR;
	}

	for (i = 0; i < data_size; i++) {
	    tloge("data[%d] = 0x%x\n", i, data[i]);
	}

	/*ret = pthread_mutex_lock(get_tee2atf_lock());
	if (ret != SRE_OK) {
		tloge("%s:Wait g_tee2atf_lock failed: %x!\n", __func__, ret);
		return ret;
	}*/
	/* map default: cacheable */
	if (sre_mmap(HISI_ATF_TEE_SHMEM_ADDR, HISI_ATF_TEE_SHMEM_SIZE,
		     &map_dst_addr, secure, cache)) {
		tloge("%s: data buffer map failed!\n", __func__);
		ret = ESE_TRS_DATA_ERR;
		goto err;
	}
	tloge("%s: sre_mmap success and memcpy start!\n", __func__);

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
	__dma_flush_range(map_dst_addr, map_dst_addr + data_size);
	tloge("%s: flush data success!\n", __func__);

	/* just return it, it's the same design of return-value in atf */
	ret = __smc_switch_to_atf(HISI_SMC_FID, &ese_smc_data);
	tloge("%s: __smc_switch_to_atf ret = 0x%x!\n", __func__, ret);
	if (ret != 0)
		tloge("%s TRANSMIT! error ret %d\n", __func__, ret);

	ret = memset_s((void *)(uintptr_t)map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE, 0, data_size + SIZE);
	if (ret != EOK) {
		tloge("%s clear data, error ret %d\n", __func__, ret);
		(void)sre_unmap(map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE);
		goto err;
	}
	(void)sre_unmap(map_dst_addr, HISI_ATF_TEE_SHMEM_SIZE);
	tloge("%s: end!\n", __func__);

err:
	/*if (pthread_mutex_unlock(get_tee2atf_lock()) != SRE_OK) {
		ret = ESE_FAILURE;
		tloge("%s:Release g_tee2atf_lock failed: %x!\n", __func__, ret);
	}*/
	return ret;
}
