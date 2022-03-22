/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: os adapter
 * Author     : security-engine
 * Create     : 2018/08/13
 */
#include <osl_os_plat.h>
#include <sre_errno.h>
#include <sre_typedef.h>
#include <pthread.h>
#include <common_utils.h>
#include <pal_log.h>

/* set the module to which the file belongs
 * each .C file needs to be configured
 */
#define BSP_THIS_MODULE BSP_MODULE_SYS

/**
 * @brief struct for mutex
 */
struct osl_mutex_s {
	enum sec_bool_e inited;
	pthread_mutex_t lock;
};

struct osl_mutex_s g_osl_mutexs[OSA_MUTEX_MAX];
#define osl_mutex_chk(hdl) (((hdl) >= g_osl_mutexs) && \
			    (hdl) < g_osl_mutexs + ARRAY_SIZE(g_osl_mutexs))

/**
 * @brief      : initialize mutex
 */
PRIVATE err_bsp_t osl_mutex_init(void)
{
	int32_t ret;
	struct osl_mutex_s *pmutex = NULL;

	for (pmutex = g_osl_mutexs;
	     pmutex < g_osl_mutexs + ARRAY_SIZE(g_osl_mutexs);
	     pmutex++) {
		if (pmutex->inited == SEC_TRUE)
			continue;

		ret = pthread_mutex_init(&pmutex->lock, NULL);
		if (ret != SRE_OK) {
			PAL_PRINTF("create mutex failed for index = %d, ret = %d\n",
				   (pmutex - g_osl_mutexs), ret);
			return ERR_HAL(ERRCODE_SYS);
		}
		pmutex->inited = SEC_TRUE;
	}
	return BSP_RET_OK;
}

/**
 * @brief      : get mutex handle
 * @param[in]  : mid ::osl_mutex_id
 */
pal_handle_t osl_mutex_get(u32 mid)
{
	if (PAL_CHECK(mid >= ARRAY_SIZE(g_osl_mutexs)))
		return NULL;
	else
		return &g_osl_mutexs[mid];
}

err_bsp_t osl_mutex_lock(pal_handle_t handle)
{
	int32_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	struct osl_mutex_s *pmutex = (struct osl_mutex_s *)handle;

	if (PAL_CHECK(!osl_mutex_chk(pmutex)))
		return ERR_HAL(ERRCODE_INVALID);

	/* task mutex */
	if (PAL_CHECK(pmutex->inited != SEC_TRUE))
		return ERR_HAL(ERRCODE_INVALID);

	ret = pthread_mutex_lock(&pmutex->lock);
	if (PAL_CHECK(ret != SRE_OK)) {
		PAL_PRINTF("osl_mutex: wait lock failed: 0x%x!\n", ret);
		ret = ERR_HAL(ERRCODE_SYS);
	} else {
		ret = BSP_RET_OK;
	}
	return ret; /*lint !e454 for mutex lock function adapter */
}

err_bsp_t osl_mutex_unlock(pal_handle_t handle)
{
	int32_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	struct osl_mutex_s *pmutex = (struct osl_mutex_s *)handle;

	if (PAL_CHECK(!osl_mutex_chk(pmutex)))
		return ERR_HAL(ERRCODE_INVALID);

	/* task mutex */
	if (PAL_CHECK(pmutex->inited != SEC_TRUE))
		return ERR_HAL(ERRCODE_INVALID);

	ret = pthread_mutex_unlock(&pmutex->lock); /*lint !e455 for mutex unlock adapter */
	if (PAL_CHECK(ret != SRE_OK)) {
		PAL_PRINTF("osl_mutex: unlock failed: 0x%x!\n", ret);
		ret = ERR_HAL(ERRCODE_SYS);
	} else {
		ret = BSP_RET_OK;
	}
	return ret;
}

/**
 * @brief      : operation system resources initialize
 */
err_bsp_t osl_os_init(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	UNUSED(ret);

	ret = osl_mutex_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}

