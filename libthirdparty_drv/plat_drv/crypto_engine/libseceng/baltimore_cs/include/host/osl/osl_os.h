/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: os adapter interface
 * Author     : security-engine
 * Create     : 2018/08/13
 */
#ifndef __OSL_OS_H__
#define __OSL_OS_H__
#include <common_define.h>
#include <common_utils.h>
#include <osl_os_plat.h>

#define OSA_WAIT_FOR_EVER    (-1)
#define OSA_DEFAULT_HANDLE   ((pal_handle_t)PTR(BSP_RET_OK))

#define osa_handle_is_def(hdl) \
	(((hdl) == OSA_DEFAULT_HANDLE) ? \
		BSP_RET_OK : ERR_BSP(BSP_MODULE_SYS, ERRCODE_INVALID))

#ifdef OSA_NO_NEED_INIT
static inline err_bsp_t osl_os_init(void)
{
	return BSP_RET_OK;
}

#else
/**
 * @brief      : operation system resources initialize
 */
err_bsp_t osl_os_init(void);

#endif  /* OSA_NO_NEED_INIT */

#ifdef OSA_NO_NEED_MUTEX
enum osl_mutex_id {
	OSA_MUTEX_GATE_CLK,
	OSA_MUTEX_ECC_IP_LOCK,
	OSA_MUTEX_RSA_IP_LOCK,
	OSA_MUTEX_SM9_IP_LOCK,

	OSA_MUTEX_SYMM_IP_LOCK,
	OSA_MUTEX_SCE2_IP_LOCK,

	/* must be at the end */
	OSA_MUTEX_MAX,
};

static inline pal_handle_t osl_mutex_get(u32 mid)
{
	UNUSED(mid);
	return OSA_DEFAULT_HANDLE;
}

static inline err_bsp_t osl_mutex_lock(pal_handle_t handle)
{
	return osa_handle_is_def(handle);
}

static inline err_bsp_t osl_mutex_unlock(pal_handle_t handle)
{
	return osa_handle_is_def(handle);
}

#define OSL_MUTEX_RUN_FUNC(pret, mid, run_func) do {\
	UNUSED(mid); \
	*(pret) = run_func; \
} while (0)

#else
/**
 * @brief      : get mutex handle
 * @param[in]  : mid ::osl_mutex_id
 */
pal_handle_t osl_mutex_get(u32 mid);

/**
 * @brief      : wait for mutex available
 * @param[in]  : handle mutex lock handle
 */
err_bsp_t osl_mutex_lock(pal_handle_t handle);

/**
 * @brief      : release mutex to be available
 * @param[in]  : handle mutex lock handle
 */
err_bsp_t osl_mutex_unlock(pal_handle_t handle);

#define OSL_MUTEX_RUN_FUNC(pret, mid, run_func) do { \
	err_bsp_t __tmp_ret; \
	pal_handle_t __tmp_hdl = osl_mutex_get(mid); \
	*(pret) = osl_mutex_lock(__tmp_hdl); \
	if (*(pret) == BSP_RET_OK) { \
		*(pret) = run_func; \
		__tmp_ret = osl_mutex_unlock(__tmp_hdl); \
		if (*(pret) == BSP_RET_OK) \
			*(pret) = __tmp_ret; \
	} \
} while (0)

#endif /* OSA_NO_NEED_MUTEX */

#define OSL_MUTEX_RUN_NO_RET(mid, run_func) do {\
	err_bsp_t __tmp_no_ret; \
	OSL_MUTEX_RUN_FUNC(&__tmp_no_ret, mid, run_func); \
	if (PAL_CHECK(__tmp_ret != BSP_RET_OK)) \
		PAL_ERROR("ret = " PAL_FMT_HEX "\n", __tmp_no_ret); \
} while (0)

#ifdef OSA_NO_NEED_EVENT
enum osl_event_id {
	OSA_EVENT_ECC,
	OSA_EVENT_RSA,

	OSA_EVENT_MAX,
};

static inline pal_handle_t osl_event_get(u32 evid)
{
	UNUSED(evid);
	return NULL;
}

static inline void osl_event_clear(pal_handle_t handle)
{
	UNUSED(handle);
}

static inline err_bsp_t osl_event_report(pal_handle_t handle, err_bsp_t result)
{
	UNUSED(result);
	UNUSED(handle);
	return ERR_BSP(BSP_MODULE_SYS, ERRCODE_UNSUPPORT);
}

static inline err_bsp_t osl_event_wait(pal_handle_t handle, int timeoutus)
{
	UNUSED(timeoutus);
	UNUSED(handle);
	return ERR_BSP(BSP_MODULE_SYS, ERRCODE_UNSUPPORT);
}

#else
/**
 * @brief      : get event handle
 * @param[in]  : evid ::osl_event_id
 */
pal_handle_t osl_event_get(u32 evid);

/**
 * @brief      : clear event
 * @param[in]  : handle event handle
 */
void osl_event_clear(pal_handle_t handle);

/**
 * @brief      : report event message
 * @param[in]  : handle event handle
 * @param[in]  : result event result
 */
err_bsp_t osl_event_report(pal_handle_t handle, err_bsp_t result);

/**
 * @brief      : wait for event to be reported
 * @param[in]  : handle event handle
 * @param[in]  : timeoutus waiting timeout (us)
 */
err_bsp_t osl_event_wait(pal_handle_t handle, int timeoutus);
#endif /* OSA_NO_NEED_EVENT */

#endif /* end of __OSL_OS_H__ */
