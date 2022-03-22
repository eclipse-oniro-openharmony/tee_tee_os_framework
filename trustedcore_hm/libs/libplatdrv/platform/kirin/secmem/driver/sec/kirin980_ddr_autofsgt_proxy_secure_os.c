#ifdef DEF_ENG
#include <stdlib.h>
#endif
#include <errno.h>
#include "hisi_ddr_autofsgt_proxy_secure_os.h"
#include <pthread.h>
#include <sre_typedef.h>

/*FOR IPC*/



/*lint -e750 -esym(750, *)*/
#define BIT(n)				        (1U << (n))
#define writel(val, addr)           ((*(volatile unsigned int *)((unsigned long)(addr))) = (val))
#define readl(addr)				    (*(volatile unsigned int *)((unsigned long)(addr)))
/*lint -restore*/

extern void uart_printf_func(const char *fmt, ...);
#define DDR_INFO uart_printf_func



#define SOC_ACPU_PERI_CRG_BASE_ADDR             (0xFFF35000U)
#define SOC_CRGPERIPH_PEREN11_ADDR(base)        ((base) + (0x460))
#define SOC_CRGPERIPH_PERDIS11_ADDR(base)       ((base) + (0x464))
#define SOC_CRGPERIPH_PERI_COMMON_CTRL1_ADDR(base)       ((base) + (0x724))



unsigned int g_autofsgt_dis_cnt = 0;
pthread_mutex_t g_pthread_lock = {0};


int ddr_autofsgt_bypass(unsigned int client, unsigned int bypass)
{
	int ret;
	(void)client;

	ret = pthread_mutex_lock(&g_pthread_lock);
	if (SRE_OK != ret) {
		DDR_INFO("%s:Wait lock_flag failed: %x!\n", __func__, ret);
		return ret;
	}

	if (bypass) {
		if (0xFFFFFFFF == g_autofsgt_dis_cnt) {
			DDR_INFO("error:g_autofsgt_dis_cnt is 0xFFFFFFFF!\n");
#ifdef DEF_ENG
			abort();
#endif
		}
		else {
			g_autofsgt_dis_cnt++;
		}
		if (1 == g_autofsgt_dis_cnt) { /*first time*/
			writel(BIT(DDR_AUTOFSGT_CLIENT_SECURE_OS + WRITE_MASK_SHIFT)| BIT(DDR_AUTOFSGT_CLIENT_SECURE_OS), SOC_CRGPERIPH_PERI_COMMON_CTRL1_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR));
		}
	} else {
		if (0 == g_autofsgt_dis_cnt) {
			DDR_INFO("error:g_autofsgt_dis_cnt is 0!\n");
#ifdef DEF_ENG
			abort();
#endif
		}
		else {
			g_autofsgt_dis_cnt--;
		}
		if (0 == g_autofsgt_dis_cnt) { /*last time*/
			writel(BIT(DDR_AUTOFSGT_CLIENT_SECURE_OS + WRITE_MASK_SHIFT), SOC_CRGPERIPH_PERI_COMMON_CTRL1_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR));
		}
	}

	ret = pthread_mutex_unlock(&g_pthread_lock);
	if (SRE_OK != ret) {
		DDR_INFO("%s:Release lock_flag failed: %x!\n", __func__, ret);
		return ret;
	}

	return 0;
}

int ddr_autofsgt_opt(unsigned int client, unsigned int cmd)
{

	switch (cmd) {
	case DDR_AUTOFSGT_LOGIC_EN:
		ddr_autofsgt_bypass(client, 0);
		break;

	case DDR_AUTOFSGT_LOGIC_DIS:
		ddr_autofsgt_bypass(client, 1);
		break;
	default:
		return -EINVAL;

	}

	return 0;

}
/*与刘军确认，外部保证互斥，此处不需要互斥*/
/*s32 ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_ID client, DDR_AUTOFSGT_CMD_ID cmd)*/
int ddr_autofsgt_ctrl(unsigned int client, unsigned int cmd)
{
	int ret;
	unsigned int opt_cmd = 0;

	switch (cmd) {
	case DDR_AUTOFSGT_LOGIC_EN:
		/*no bypass*/
		opt_cmd = DDR_AUTOFSGT_LOGIC_EN;
		break;

	case DDR_AUTOFSGT_LOGIC_DIS:
		/*bypass*/
		opt_cmd = DDR_AUTOFSGT_LOGIC_DIS;
		break;
	default:
		return -EINVAL;
	}

		ret = ddr_autofsgt_opt(client, opt_cmd);

		if (ret) {
			DDR_INFO("[%s] opt_cmd err:[0x%x]\n", __func__, opt_cmd);
			return -EINVAL;
		}


	return 0;
}

int ddr_autofsgt_proxy_init(void)
{
	return 0;
}
/*lint -restore*/

