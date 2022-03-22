/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
* Description: This file processes hieps exception include alarm.
* Create: 2019-01-31
*/


#include <sre_sys.h>
#include <sre_typedef.h>
#include <sre_hwi.h>
#include <secure_gic_common.h>
#include <tee_log.h>
#include <hieps_errno.h>
#include <hieps_exception.h>
#include <hieps_ipc.h>
#include <hieps_common.h>
#include <hieps_pm.h>
#include <hieps_timer.h>
#include <hieps_power.h>

/* Store soft exception count. */
static uint32_t g_hieps_reset_cnt;
/* Indicate whether soft excetption is happened or not. */
static uint32_t g_hieps_exception_flag = HIEPS_EXCEPTION_DONE;


/*
 * @brief      : hieps_get_reset_cnt : Get current count of exception.
 *
 * @return     : The count of exception.
 */
static uint32_t hieps_get_reset_cnt()
{
	return g_hieps_reset_cnt;
}

/*
 * @brief      : hieps_update_reset_cnt : Add the exception count.
 */
static void hieps_update_reset_cnt()
{
	g_hieps_reset_cnt++;
}

/*
 * @brief      : hieps_clear_reset_cnt : Clear the count of exception.
 */
static void hieps_clear_reset_cnt()
{
	g_hieps_reset_cnt = 0;
}

/*
 * @brief      : hiep_set_soft_exception_flag : Set soft exception flag.
 */
static void hiep_set_soft_exception_flag(void)
{
	g_hieps_exception_flag = HIEPS_EXCEPTION_DOING;
}

/*
 * @brief      : hiep_get_soft_exception_flag : Get soft exception flag.
 *
 * @return     : 
 */
uint32_t hiep_get_soft_exception_flag(void)
{
	return g_hieps_exception_flag;
}

/*
 * @brief      : hiep_clear_soft_exception_flag : Clear soft exception flag.
 */
void hiep_clear_soft_exception_flag(void)
{
	g_hieps_exception_flag = HIEPS_EXCEPTION_DONE;
}

/*
 * @brief      : hieps_exception_handler : Process hieps soft exception.
 *
 * @param[in]  : msg : the data from ipc.
 */
static int32_t hieps_exception_handler(ipc_msg_t *msg)
{
	uint32_t excpt_version, fault_id, fault_value;
	static uint64_t start_time = 0;
	static uint64_t end_time;
	uint64_t max_time_cnt = 0;
	hieps_reset_strategy strategy = HIEPS_EXCPT_RESET;

	hiep_set_soft_exception_flag();

	/* Ipc data2 reg store the exception version.*/
	excpt_version = msg->data[2];
	if (excpt_version == HIEPS_TEEOS_EXCPT_VERSION2) {
		/* Ipc data3 reg store the fault id. */
		fault_id = msg->data[3];
		/* Ipc data4 reg store the fault value. */
		fault_value = msg->data[4];
	} else {
		/* Ipc data3 reg store the fault id and fault value. */
		fault_value = msg->data[3];
		fault_value &= ~HIEPS_EXC_HEAD_MASK; /* Mask the head. */
		fault_id = fault_value >> HIEPS_EXC_TYPE_OFFSET;
		fault_value &= HIEPS_EXC_VALUE_MASK;
	}

	tloge("hieps exception: fault_id:0x%x, fault_value:0x%x\n",\
		fault_id, fault_value);

	/* If hieps has 5 exceptions in 3s, donot power on hieps */
	if (!start_time) {
		start_time = hieps_get_timer_value();
	}

	max_time_cnt = US2TICK((uint64_t)HIEPS_RESET_TIME);
	end_time = hieps_get_timer_value();
	if ((end_time - start_time) < max_time_cnt) {
		hieps_update_reset_cnt();
	} else {
		start_time = 0;
		hieps_clear_reset_cnt();
	}

	if (hieps_get_reset_cnt() >= HIEPS_MAX_RESET_CNT) {
		hieps_clear_power_status();
		strategy = HIEPS_EXCPT_OFF;
		tloge("hieps exception: receive too much exception!\n");
	}

	hieps_exception_reset(HIEPS_SOFT_EXCEPTION, strategy);
	hiep_clear_soft_exception_flag();
	return HIEPS_OK;
}

/*
 * @brief      : hieps_exception_init : Initialize hieps exception module.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
int32_t hieps_exception_init(void)
{
	int32_t ret;

	/* Register hieps ipc handler to process soft exception. */
	ret = hieps_ipc_msg_req_callback(OBJ_HIEPS, CMD_SETTING,\
					hieps_exception_handler);
	if (ret != HIEPS_OK) {
		tloge("hieps:Register ipc callback failed: 0x%x\n", ret);
		return ret;
	}

	return ret;
}

/*
 * @brief      : hieps_exception_resume : Resume the hieps exception module.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
int32_t hieps_exception_resume(void)
{
	return HIEPS_OK;
}

