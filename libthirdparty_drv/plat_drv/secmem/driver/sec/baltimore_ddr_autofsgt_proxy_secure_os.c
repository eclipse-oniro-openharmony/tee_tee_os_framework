#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sre_typedef.h>
#include <tee_log.h>
#include <soc_acpu_baseaddr_interface.h>
#include <soc_crgperiph_interface.h>
#include <ddr_define.h>
#include <hisi_ddr_autofsgt_proxy.h>


#define OK							0
#define ERROR						-1
#define BIT(n)						(1U << (n))
#define writel(val, addr)			((*(volatile unsigned int *)((unsigned long)(addr))) = (val))
#define readl(addr)					(*(volatile unsigned int *)((unsigned long)(addr)))
#define DDR_INFO					uart_printf_func


unsigned int g_autofsgt_bypass_cnt = 0;
unsigned int g_ddr_autogt_bypass_flag = 0;
pthread_mutex_t g_pthread_lock = {0};


int ddr_autofsgt_bypass(unsigned int client, unsigned int cmd)
{
	int ret;

	ret = pthread_mutex_lock(&g_pthread_lock);
	if (ret != SRE_OK) {
		DDR_INFO("%s:Wait lock_flag failed: %x!\n", __func__, ret);
		return ret;
	}

	if (cmd == DDR_AUTOFSGT_LOGIC_DIS) {
		if ((g_ddr_autogt_bypass_flag & BIT(client)) != 0) {
			DDR_INFO("DDR AUTOGT BYPASS ERROR: bit(%x) exit\n", client);
#ifdef DEF_ENG
			abort();
#endif
			return ERROR;
		}
		g_ddr_autogt_bypass_flag |= BIT(client);
		g_autofsgt_bypass_cnt += 1;
		if (g_autofsgt_bypass_cnt == 1) {	/* first time */
			writel(BIT(DDR_AUTOFSGT_BIT_SECURE_OS + WRITE_MASK_SHIFT) | BIT(DDR_AUTOFSGT_BIT_SECURE_OS), SOC_CRGPERIPH_PERI_COMMON_CTRL1_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR));
		}
	} else {
		if ((g_ddr_autogt_bypass_flag & BIT(client)) == 0) {
			DDR_INFO("DDR AUTOGT DISABLE BYPASS ERROR: bit(%x) not exit\n", client);
#ifdef DEF_ENG
			abort();
#endif
			return ERROR;
		}
		g_ddr_autogt_bypass_flag &= ~BIT(client);
		g_autofsgt_bypass_cnt -= 1;
		if (g_autofsgt_bypass_cnt == 0) {	/* last time */
			writel(BIT(DDR_AUTOFSGT_BIT_SECURE_OS + WRITE_MASK_SHIFT), SOC_CRGPERIPH_PERI_COMMON_CTRL1_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR));
		}
	}

	ret = pthread_mutex_unlock(&g_pthread_lock);
	if (ret != SRE_OK) {
		DDR_INFO("%s:Release lock_flag failed: %x!\n", __func__, ret);
		return ret;
	}

	return 0;
}

int ddr_autofsgt_ctrl(unsigned int client, unsigned int cmd)
{
	int ret;
	unsigned int opt_cmd = 0;

	switch (cmd) {
	case DDR_AUTOFSGT_LOGIC_EN:
		/* no bypass */
		opt_cmd = DDR_AUTOFSGT_LOGIC_EN;
		break;
	case DDR_AUTOFSGT_LOGIC_DIS:
		/* bypass */
		opt_cmd = DDR_AUTOFSGT_LOGIC_DIS;
		break;
	default:
		return -EINVAL;
	}
	ret = ddr_autofsgt_bypass(client, opt_cmd);
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
