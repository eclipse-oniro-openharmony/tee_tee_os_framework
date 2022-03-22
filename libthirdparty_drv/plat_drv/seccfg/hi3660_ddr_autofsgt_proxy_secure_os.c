#include <errno.h>
#include "hisi_ddr_autofsgt_proxy_secure_os.h"
/*FOR HWLOCK*/
#include "hwspinlock.h"
#include "sre_log.h"

#if defined (CONFIG_HISI_DDR_AUTO_FSGT)

#undef CONFIG_HISI_DDR_AUTO_FSGT_IPC
#define CONFIG_HISI_DDR_AUTO_FSGT_HWLOCK

/*lint -save -e717 -e716 -e722 -e750*/
#define BIT(n)				(1U << (n))
#define writel(val, addr)		((*(volatile unsigned int *)((unsigned long)(addr))) = (val))
#define readl(addr)			(*(volatile unsigned int *)((unsigned long)(addr)))
#define set_bit(nr, addr)           do{writel((((unsigned int)readl(addr))|(unsigned int)BIT(nr)), (addr));}while(0)
#define clear_bit(nr, addr)         do{writel((((unsigned int)readl(addr))&(~((unsigned int)BIT(nr)))), (addr));}while(0)
/*lint -restore*/


/*lint -e750 -esym(750, *)*/
#define SOC_ACPU_IPC_BASE_ADDR                  (0xE896A000)
#define SOC_IPC_LOCK_ADDR(base)                 ((base) + (0xA00))
#define SOC_IPC_MBX_MODE_ADDR(base, i)          ((base) + (0x010+(i)*64))
#define SOC_IPC_MBX_SOURCE_ADDR(base, i)        ((base) + (0x000+(i)*64))
#define SOC_IPC_MBX_IMASK_ADDR(base, i)         ((base) + (0x014+(i)*64))
#define SOC_IPC_MBX_DATA0_ADDR(base, i)         ((base) + (0x020+(i)*64))
#define SOC_IPC_MBX_DATA1_ADDR(base, i)         ((base) + (0x024+(i)*64))
#define SOC_IPC_MBX_SEND_ADDR(base, i)          ((base) + (0x01C+(i)*64))
#define SOC_IPC_MBX_MODE_ADDR(base, i)          ((base) + (0x010+(i)*64))
#define SOC_IPC_MBX_ICLR_ADDR(base, i)          ((base) + (0x018+(i)*64))
#define IPC_UNLOCK_VALUE                        (0x1ACCE551)
#define IPC_STATE_IDLE                          (0x10)
#define LPM3_MBX23                              (23)
#define SRC_A57                                 (0) /*是否需要与bl31的值不一样*/
#define SRC_LPM3                                (3)
#define IPC_ACK_MASK                            (1<<7)
#define IPC_CMD                                 (0<<24|0x4<<16|0x4<<8|0x2)
#define IPC_PARA(send)                          ((send)<<8|DDR_AUTOFSGT_CLIENT_SECURE_OS)
/*lint -e750 +esym(750, *)*/

/*FOR HWLOCK*/
#define SOC_ACPU_PERI_CRG_BASE_ADDR             (0xFFF35000U)
#define SOC_CRGPERIPH_PEREN11_ADDR(base)        ((base) + (0x460))
#define SOC_CRGPERIPH_PERDIS11_ADDR(base)       ((base) + (0x464))
#define SOC_ACPU_SCTRL_BASE_ADDR                (0xFFF0A000U)
#define SOC_SCTRL_SCBAKDATA7_ADDR(base)         ((base) + (0x428))
#define SCBAKDATA_MASK                          (0xFFFF0000U)
#define SCBAKDATA_BIT                           (16 + DDR_AUTOFSGT_CLIENT_SECURE_OS)
#define DDR_AUTOFSGT_LOCK_ID                    (25)


static unsigned int g_ddr_autofsgt_disable_flag = 0;
static unsigned int g_ddr_autofsgt_bypass_flag = 0;
static unsigned int g_ddr_autofsgt_sw = 1;

/*lint -save -e717 -e716 -e722 -e750*/
#if defined (CONFIG_HISI_DDR_AUTO_FSGT_IPC)
static void cpu_relax(void)
{
	volatile int i;

	for (i = 0; i < 10; i++) {
		__asm__ volatile("nop");
	}
}

int ddr_autofsgt_ipc_send(unsigned int cmdtype, unsigned int cmdpara)
{
	unsigned int regval = 0;

	/*unlock reg*/
	writel(IPC_UNLOCK_VALUE, SOC_IPC_LOCK_ADDR(SOC_ACPU_IPC_BASE_ADDR));

	/*wait for idle and occupy*/
	do {
		if (IPC_STATE_IDLE == readl(SOC_IPC_MBX_MODE_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23))) {
			writel(BIT(SRC_A57), SOC_IPC_MBX_SOURCE_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));
			regval = readl(SOC_IPC_MBX_SOURCE_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));

			if (regval == BIT(SRC_A57))
				break;
		}

		cpu_relax();
	} while (1);

	/*mask the other cpus*/
	writel((~(BIT(SRC_A57) | BIT(SRC_LPM3))), SOC_IPC_MBX_IMASK_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));

	/*set data*/
	writel(cmdtype, SOC_IPC_MBX_DATA0_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));
	writel(cmdpara, SOC_IPC_MBX_DATA1_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));
	/*send cmd*/
	writel(BIT(SRC_A57), SOC_IPC_MBX_SEND_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));

	/*wait ack and clear*/
	do {
		regval = readl(SOC_IPC_MBX_MODE_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));
		cpu_relax();
	} while (regval != IPC_ACK_MASK);

	writel(BIT(SRC_A57), SOC_IPC_MBX_ICLR_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));

	/*release mailbox*/
	writel(BIT(SRC_A57), SOC_IPC_MBX_SOURCE_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));
	return (int)readl(SOC_IPC_MBX_DATA1_ADDR(SOC_ACPU_IPC_BASE_ADDR, LPM3_MBX23));
}
#endif

#if defined (CONFIG_HISI_DDR_AUTO_FSGT_HWLOCK)

int ddr_autofsgt_bypass(int enable)
{
	if (enable) {
		writel(0x40000000, SOC_CRGPERIPH_PEREN11_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR));
	} else {
		writel(0x40000000, SOC_CRGPERIPH_PERDIS11_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR));
	}

	return 0;
}

int ddr_autofsgt_hwlock_opt(unsigned int opt_cmd)
{
	unsigned int regval = 0;

	switch (opt_cmd) {
	case DDR_AUTOFSGT_LOGIC_EN:

		if (HS_OK == hwspin_lock_timeout(DDR_AUTOFSGT_LOCK_ID, WAITFVR)) {
			regval = readl(SOC_SCTRL_SCBAKDATA7_ADDR(SOC_ACPU_SCTRL_BASE_ADDR));
			clear_bit(SCBAKDATA_BIT, &regval);
			writel(regval, SOC_SCTRL_SCBAKDATA7_ADDR(SOC_ACPU_SCTRL_BASE_ADDR));

			if (!(regval & SCBAKDATA_MASK)) {
				ddr_autofsgt_bypass(0);
			}

			hwspin_unlock(DDR_AUTOFSGT_LOCK_ID);
		} else {
			while (1);
		}

		break;

	case DDR_AUTOFSGT_LOGIC_DIS:

		if (HS_OK == hwspin_lock_timeout(DDR_AUTOFSGT_LOCK_ID, WAITFVR)) {
			regval = readl(SOC_SCTRL_SCBAKDATA7_ADDR(SOC_ACPU_SCTRL_BASE_ADDR));
			set_bit(SCBAKDATA_BIT, &regval);
			writel(regval, SOC_SCTRL_SCBAKDATA7_ADDR(SOC_ACPU_SCTRL_BASE_ADDR));
			ddr_autofsgt_bypass(1);
			hwspin_unlock(DDR_AUTOFSGT_LOCK_ID);
		} else {
			while (1);
		}

		break;
	default:
		return -EINVAL;

	}

	return 0;
}

#endif
int ddr_autofsgt_opt(unsigned int opt_cmd)
{
#if defined (CONFIG_HISI_DDR_AUTO_FSGT_IPC)
	return ddr_autofsgt_ipc_send(IPC_CMD, IPC_PARA(opt_cmd));
#endif

#if defined (CONFIG_HISI_DDR_AUTO_FSGT_HWLOCK)
	return ddr_autofsgt_hwlock_opt(opt_cmd);
#endif
}

/*与刘军确认，外部保证互斥，此处不需要互斥*/
/*s32 ddr_autofsgt_ctrl(DDR_AUTOFSGT_PROXY_CLIENT_ID client, DDR_AUTOFSGT_CMD_ID cmd)*/
int ddr_autofsgt_ctrl(unsigned int client, unsigned int cmd)
{
	int ret = 0;
	unsigned int opt_cmd = 0;

	switch (cmd) {
	case DDR_AUTOFSGT_ENABLE:
		clear_bit(client, &g_ddr_autofsgt_disable_flag);

		if (!g_ddr_autofsgt_disable_flag) {
			/*enable*/
			opt_cmd = DDR_AUTOFSGT_ENABLE;
		}

		break;

	case DDR_AUTOFSGT_DISABLE:

		if (!g_ddr_autofsgt_disable_flag) {
			/*disable*/
			opt_cmd = DDR_AUTOFSGT_DISABLE;
		}

		set_bit(client, &g_ddr_autofsgt_disable_flag);
		break;

	case DDR_AUTOFSGT_LOGIC_EN:
		clear_bit(client, &g_ddr_autofsgt_bypass_flag);

		if (!g_ddr_autofsgt_bypass_flag) {
			/*no bypass*/
			opt_cmd = DDR_AUTOFSGT_LOGIC_EN;
		}

		break;

	case DDR_AUTOFSGT_LOGIC_DIS:

		if (!g_ddr_autofsgt_bypass_flag) {
			/*bypass*/
			opt_cmd = DDR_AUTOFSGT_LOGIC_DIS;
		}

		set_bit(client, &g_ddr_autofsgt_bypass_flag);
		break;
	default:
		return -EINVAL;
	}

	if (opt_cmd && g_ddr_autofsgt_sw) {
		/*send ipc*/
		ret = ddr_autofsgt_opt(opt_cmd);

		if (ret) {
			tlogd("[%s] opt_cmd err:[0x%x]\n", __func__, opt_cmd);
			return -EINVAL;
		}
	}


	return 0;
}

/*lint -restore*/
#else

int ddr_autofsgt_ctrl(unsigned int client, unsigned int cmd)
{
	return 0;
}
#endif
