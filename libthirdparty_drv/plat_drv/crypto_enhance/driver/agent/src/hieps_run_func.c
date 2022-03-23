/****************************************************************************//**
 * @file   : pal_ipc.c
 * @brief  :
 * @par    : Copyright (c) 2018-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/19
 * @author : m00172947
 * @note   :
********************************************************************************/
#include <stdarg.h>
#include <common_utils.h>
#include <hieps_agent.h>
#include <hieps_errno.h>
#include <hieps_cdrm_cmd.h>
#include <pal_libc.h>
#include <pal_timer.h>

/*===============================================================================
 *                               types/macros                                  *
===============================================================================*/
/* set the module to which the file belongs
   each .C file needs to be configured
*/
#define BSP_THIS_MODULE BSP_MODULE_SYS

#define HIEPS_RUN_FUNC_WAIT_US      (5)

/*===============================================================================
 *                               global objects                                *
===============================================================================*/


/*===============================================================================
 *                                 functions                                   *
===============================================================================*/
/****************************************************************************//**
 * @brief      : hieps_run_func
 * @param[in]  : timeout_us timeout if -1, no timeout
 * @param[in]  : func_id     funciton identifier
 * @param[in]  : params_num  funciton parameter number
 * @return     : ::err_bsp_t
 * @note       :
********************************************************************************/
err_bsp_t hieps_run_func(int timeout_us, u32 func_id, u32 params_num, ...)
{
	err_bsp_t ret  = ERR_DRV(ERRCODE_UNKNOWN);
	u8  *tee_pack  = NULL;
	u8  *eps_pack  = NULL;
	u32  pack_size = sizeof(func_header_s) + WORD2BYTE(params_num);
	u32  ipc_ret   = 0;
	s32  counter   = 0;
	volatile func_header_s   *pheader  = NULL;
	volatile hieps_cdrm_msg_t cdrm_msg = { 0 };
	errno_t libc_ret;

	/* check param */
	PAL_CHECK_RETURN((FUNC_PARAMS_MAX <= params_num), ERR_DRV(ERRCODE_PARAMS));

	/* malloc for pack */
	tee_pack = hieps_mem_new(NULL, pack_size);
	PAL_CHECK_RETURN((NULL == tee_pack), ERR_DRV(ERRCODE_MEMORY));

	/* convert address */
	eps_pack = (u8 *)hieps_mem_convert2hieps(tee_pack);
	PAL_CHECK_GOTO((NULL == eps_pack), ERR_DRV(ERRCODE_INVALID), RUN_FUNC_END);

	pheader = (func_header_s *)tee_pack;
	pheader->ret       = ret;
	pheader->id        = func_id;
	pheader->timestamp = pal_timer_value();

	/* add parameters in pack */
	/* compiler push params on stack from right to left one by one, so we can get params from stack */
	/* +-----------+
	   | param n   | stack, high address
	   +-----------+
	   | param n-1 |
	   +-----------+
	   | param ... |
	   +-----------+ get params from here to high address
	   | params_num|
	   +-----------+
	   | func_id   |
	   +-----------+
	   | timeout_us| stack, low address
	   +-----------+ */
	va_list argptr;
	u32 temp;
	va_start(argptr, params_num);
	for (u32 i = 0; i < params_num; ++i) {
		temp = va_arg(argptr, u32);
		libc_ret = memcpy_s(tee_pack + sizeof(func_header_s) +  i * sizeof(temp),
			pack_size - sizeof(func_header_s) - i * sizeof(temp),
			&temp, sizeof(temp));
		PAL_CHECK_GOTO((EOK != libc_ret), ERR_API(ERRCODE_MEMORY), RUN_FUNC_END);
	}
	va_end(argptr);
	/* send to hieps */
	ipc_ret = hieps_send_cdrm_msg((u32)(uintptr_t)eps_pack, pack_size);
	PAL_CHECK_GOTO((ipc_ret != HIEPS_OK), ERR_DRV(ERRCODE_REQUEST), RUN_FUNC_END);

	cdrm_msg = hieps_get_cdrm_msg();
	/* wait until receive response */
	while ((cdrm_msg.flag != HIEPS_CDRM_MSG_DOING) && ((timeout_us < 0) || (timeout_us > counter))) {
		pal_udelay(HIEPS_RUN_FUNC_WAIT_US);
		counter += HIEPS_RUN_FUNC_WAIT_US;
		cdrm_msg = hieps_get_cdrm_msg();
	}
	/* clear flag */
	hieps_clear_cdrm_msg();

	/* check func_id when hieps return message */
	PAL_CHECK_GOTO(func_id != pheader->id, ERR_DRV(ERRCODE_VERIFY), RUN_FUNC_END);

	if (ret != pheader->ret) {
		ret = pheader->ret;
	} else {
		pheader->timestamp = 0;
		pheader->id = FUNC_ID_MAX;
		ret = ERR_DRV(ERRCODE_TIMEOUT);
		PAL_ERROR("agent timeout for %d us, ret = "PAL_FMT_PTR" \n", timeout_us, ret);
	}

RUN_FUNC_END:
	/* release */
	hieps_mem_delete(tee_pack);
	return ret;
}

