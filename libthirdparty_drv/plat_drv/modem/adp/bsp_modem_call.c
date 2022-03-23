#include <tee_log.h> /* uart_printf_func */
#include <osl_balong.h>
#include <bsp_modem_call.h>

#define MODEM_CALL_IS_STUB   (0x901800ff)      /* 桩接口返回值 */
#define TA_TO_DRV_FUNC_MAX   (FUNC_TA_TO_DRV_MAX - FUNC_TA_TO_DRV_MIN)
#define CA_TO_DRV_FUNC_MAX   (FUNC_CA_TO_DRV_MAX - FUNC_CA_TO_DRV_MIN)
#define MODEM_CALL_FUNC_MAX  (TA_TO_DRV_FUNC_MAX + CA_TO_DRV_FUNC_MAX)

int (*modem_call_func[MODEM_CALL_FUNC_MAX])(unsigned int arg1, void *arg2, unsigned int arg3);

int bsp_modem_call_register(FUNC_CMD_ID call_id, MODEM_CALL_HOOK_FUNC modem_call)
{
	if ((call_id >= FUNC_TA_TO_DRV_MIN) && (call_id < FUNC_TA_TO_DRV_MAX)) {
		modem_call_func[call_id - FUNC_TA_TO_DRV_MIN] = modem_call;
	} else if ((call_id >= FUNC_CA_TO_DRV_MIN) && (call_id < FUNC_CA_TO_DRV_MAX)) {
		modem_call_func[(call_id - FUNC_CA_TO_DRV_MIN) + TA_TO_DRV_FUNC_MAX] = modem_call;
	} else {
		uart_printf_func("modem call register fail call_id: 0x%x\n", call_id);
		return -1;
	}
	return 0;
}

int bsp_modem_call(unsigned int func_cmd, unsigned int arg1, void *arg2, unsigned int arg3)
{
	FUNC_CMD_ID call_id;

	call_id = (FUNC_CMD_ID)func_cmd;
	if ((call_id >= FUNC_TA_TO_DRV_MIN) && (call_id < FUNC_TA_TO_DRV_MAX)) {
		call_id = call_id - FUNC_TA_TO_DRV_MIN;
	} else if ((call_id >= FUNC_CA_TO_DRV_MIN) && (call_id < FUNC_CA_TO_DRV_MAX)) {
		call_id = (call_id - FUNC_CA_TO_DRV_MIN) + TA_TO_DRV_FUNC_MAX;
	} else {
		uart_printf_func("error func_cmd: 0x%x\n", func_cmd);
		return -1;
	}

	if (modem_call_func[call_id] != NULL)
		return modem_call_func[call_id](arg1, arg2, arg3);
	else {
		uart_printf_func("modem call func is null: 0x%x\n", func_cmd);
		return (int)MODEM_CALL_IS_STUB;
	}
}

