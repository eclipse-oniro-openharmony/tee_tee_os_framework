#include "ipc_core.h"
#include "icc_core.h"

extern void os_hwi_ipc_handler(int uwArg);

void ipc_isr_test(unsigned int data)
{
	HISI_PRINT_ERROR("ipc_isr_test success\n");
	bsp_ipc_int_send(1, 0);
}

#if 0
int bsp_ipc_test_init(void)
{
	s32 ret = 0;
	ret = bsp_ipc_int_connect(IPC_ACPU_INT_SRC_CCPU_ICC_UNTASK_SHARED, (voidfuncptr)ipc_isr_test, 0);
	if (ret != BSP_OK) {
		HISI_PRINT_ERROR("bsp_ipc_test_init connect error\n");
		return BSP_ERROR;
	}
	ret = bsp_ipc_int_enable(IPC_ACPU_INT_SRC_CCPU_ICC_UNTASK_SHARED);
	if (ret != BSP_OK) {
		HISI_PRINT_ERROR("bsp_ipc_test_init enable int  error\n");
		return BSP_ERROR;
	}
	HISI_PRINT_ERROR("bsp_ipc_test_init ok\n");
	return BSP_OK;
}
#endif

struct icc_test_ac {
	unsigned int data_a;
	unsigned int data_b;
	unsigned int data_c;
	unsigned int data_d;
};
static struct icc_test_ac test_ac_recv = {0};

unsigned int g_ac_full_ch_id0 = (ICC_CHN_SEC_IFC << 16) | IFC_RECV_FUNC_MODULE_VERIFY;
unsigned int g_ac_full_ch_id1 = (ICC_CHN_SEC_VSIM << 16) | VSIM_RECV_FUNC_SUB0;

int icc_test_ac_cb(u32 channel_id , u32 len, void *context)
{
	int ret = 0;
	struct icc_test_ac test_ac_recv = {0};
	struct icc_test_ac test_ac_send = {0};

	ret = bsp_icc_read(channel_id, (u8 *)&test_ac_recv, (u32)sizeof(struct icc_test_ac));
	if (ret < (int)sizeof(struct icc_test_ac)) {
		icc_print_error("ac_cb bsp_icc_read err need to read %d bytes in fact read %d bytes\n", sizeof(struct icc_test_ac), ret);
		return -1;
	}

	test_ac_send.data_a = test_ac_recv.data_a;
	test_ac_send.data_b = test_ac_recv.data_b;
	test_ac_send.data_c = test_ac_recv.data_c;
	test_ac_send.data_d = test_ac_recv.data_d;


	/* ·¢ËÍÊý¾Ý */
	ret = bsp_icc_send(ICC_CPU_MODEM, channel_id, (u8 *)&test_ac_send, (u32)sizeof(struct icc_test_ac));
	if (ret < (int)sizeof(struct icc_test_ac)) {
		icc_print_error("bsp_icc_send error,ret=%d\n", ret);
		return -1;
	}
	os_hwi_ipc_handler(192);
	icc_print_error("ac_cb bsp_icc_send %d bytes ok\n", sizeof(struct icc_test_ac));

	return 0;
}

#if 0
int icc_test_ac_cb(u32 channel_id , u32 len, void *context)
{
	int ret = 0;

	ret = bsp_icc_read(g_ac_full_ch_id, (u8 *)&test_ac_recv, (u32)sizeof(struct icc_test_ac));
	if (ret < (int)sizeof(struct icc_test_ac)) {
		icc_print_error("ac_cb bsp_icc_read err need to read %d bytes in fact read %d bytes\n", sizeof(struct icc_test_ac), ret);
		return -1;
	}

	os_hwi_ipc_handler(192);

	icc_print_error("ac_cb bsp_icc_send %d bytes ok\n", sizeof(struct icc_test_ac));

	return 0;
}
#endif
int icc_test_ac_init(void)
{
	int ret = 0;
	icc_print_error("icc_test_ac_init start\n");
	ret = bsp_icc_event_register(g_ac_full_ch_id0, icc_test_ac_cb, NULL, NULL, NULL);
	if (ret) {
		icc_print_error("reg icc_test_ac_cb err ret=0x%08x\n", ret);
		return -1;
	}

	ret = bsp_icc_event_register(g_ac_full_ch_id1, icc_test_ac_cb, NULL, NULL, NULL);
	if (ret) {
		icc_print_error("reg icc_test_ac_cb err ret=0x%08x\n", ret);
		return -1;
	}
	icc_print_error("reg icc_test_ac_cb ok\n");

	return 0;
}

int bsp_module_verify(unsigned int *addr, unsigned int *size)
{
	*addr = test_ac_recv.data_a;
	*size = test_ac_recv.data_d;
	return 0;
}

void bsp_module_file_verify_reply(unsigned int reply)
{
	int ret;

	icc_print_error("reply = 0x%x\n", reply);
	ret = bsp_icc_send(ICC_CPU_MODEM, g_ac_full_ch_id0, (u8 *)&reply, (u32)sizeof(unsigned int));
	if (ret < (int)sizeof(unsigned int)) {
		icc_print_error("bsp_icc_send error,ret=%d\n", ret);
		return;
	}
}


/*DECLARE_TC_DRV(
			icc_test,
			0,
			0,
			0,
			TC_DRV_MODULE_INIT,
			icc_test_ac_init,
			NULL,
			NULL,
			NULL,
			NULL
);*/

