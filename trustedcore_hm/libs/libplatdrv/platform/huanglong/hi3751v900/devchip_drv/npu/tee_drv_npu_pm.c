/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: hisi npu pm
 * Author: Hisilicon
 * Create: 2020-01-16
 */
#include "hi_type_dev.h"
#include "tee_drv_npu_reg.h"
#include "tee_drv_npu_utils.h"
#include "tee_drv_npu_pm.h"
#include "hi_tee_license.h"


#define SYS_PERI_NPU_STATUS0_SUCCESS           0x00108420
#define SYS_PERI_NPU_STATUS1_SUCCESS_MASK      0xfff0000
#define SYS_PERI_NPU_STATUS_WAIT_MAX_NUM       100

/* TBU reg */
#define SMMU_TBU_CR (0)
#define TBU_EN_REQ BIT(0)

#define SMMU_TBU_CRACK (0x4)
#define TBU_EN_ACK BIT(0)
#define TBU_CONNECTED BIT(1)

#define ARM_SMMU_POLL_TIMEOUT_US   1000

#define SYS_CRG_BASE        0xa00000    // <0x0 0xa00000 0x0 0x1000>,    /*SYS_CRG*/
#define SYS_PERI_BASE       0xa10000    // <0x0 0xa10000 0x0 0x1000>,    /*SYS_PERI_CTRL*/
#define SYS_PMC_BASE        0xa15000    // <0x0 0xa15000 0x0 0x1000>,    /*SYS_PMC*/
#define NPU_TS_SUBSYS_BASE  0x4000000   // <0x0 0x4000000 0x0 0x400000>, /*TS_SYSCTRL*/
#define NPU_AICORE_BASE     0x5000000   // <0x0 0x5000000 0x0 0x100000>, /*AICORE*/
#define NPU_CFG_BASE        0x5e00000   // <0x0 0x5e00000 0x0 0x200000>, /*NPU_CRG*/
#define SYS_CTL_BASE        0x840000    // <0x0 0x0840000 0x0 0x200000>, /*SYS_CTL*/

#define HPM_MONITOR_EN (1 << 26)
#define HPM_EN (1 << 24)
#define HPM_MONITOR_PERIOD_BITS (0xff << 0)
#define HPM_MONITOR_PERIOD (0x1 << 0) /* set monitor period to 2ms */
#define HPM_DIV_BITS (0x3f << 24)
#define HPM_DIV (0x3 << 24) /* clock is 200M, set time division to (200/50-1) */
#define HPM_VALUE_BITS 0x3ff
#define NPU_VOLT_MAX 1000
#define NPU_VOLT_MIN 600
#define NPU_VMIN_BIT  0xffff
#define PWM_STEP     ((NPU_VOLT_MAX - NPU_VOLT_MIN) / PWM_STEP_NUM)
#define PWM_CLASS    2
#define PWM_STEP_NUM 110
#define REGULATOR_BASE 0x000100DD
#define REGULATOR_OFFSET (1 << 16)
#define npu_min_value(x, y) (((x) < (y)) ? (x) : (y))

int get_npu_hpm(void)
{
    unsigned int regval, hpm_value, hpm_value_average;

    regval = NPU_REG_READ(SYS_PMC_BASE, SOC_PMC_HPM5_CTRL3_OFFSET);
    regval &= ~HPM_DIV_BITS;
    regval |= HPM_DIV;
    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_HPM5_CTRL3_OFFSET, regval);

    regval = NPU_REG_READ(SYS_PMC_BASE, SOC_PMC_HPM5_CTRL0_OFFSET);
    regval &= ~HPM_MONITOR_PERIOD_BITS;
    regval |= (HPM_MONITOR_EN | HPM_MONITOR_PERIOD);
    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_HPM5_CTRL0_OFFSET, regval);

    udelay(10000); /* 10000: wait 10ms after enable hpm */

    regval = NPU_REG_READ(SYS_PMC_BASE, SOC_PMC_HPM5_CTRL1_OFFSET);
    hpm_value = (regval & HPM_VALUE_BITS) + ((regval >> 12) & HPM_VALUE_BITS); /* right shift 12 bits */

    regval = NPU_REG_READ(SYS_PMC_BASE, SOC_PMC_HPM5_CTRL2_OFFSET);
    hpm_value += (regval & HPM_VALUE_BITS) + ((regval >> 12) & HPM_VALUE_BITS); /* right shift 12 bits */

    hpm_value_average = hpm_value >> 2; /* right shift 2 bits */

    return hpm_value_average;
}

static int npu_readx_poll_timeout(u32 addr, u32 ack_bit, u32 timeout_us)
{
    u32 val;
    int looptime = 0;

    for (;; looptime++) {
        val = *(volatile u32 *)(addr);
        if (val & ack_bit)
            break;
        if (looptime > timeout_us) {
            val = *(volatile u32 *)(addr);
            break;
        }
    }
    return (val & ack_bit) ? 0 : -ETIMEDOUT;
}

int npu_reg_bit_set_with_ack(unsigned int base, unsigned int req_off,
                             unsigned int ack_off, unsigned int req_bit, unsigned int ack_bit)
{
    u32 val;

    val = NPU_REG_READ(base, req_off);
    val |= req_bit;
    NPU_REG_WRITE(base, req_off, val);
    return npu_readx_poll_timeout(base + ack_off, ack_bit, ARM_SMMU_POLL_TIMEOUT_US);
}

#ifdef NPU_USE_NO_SVM
static int npu_subsys_init(void)
{
    unsigned int smmu_tcu_cfg_base;

    smmu_tcu_cfg_base = NPU_CFG_BASE + SOC_SMMU_TCU_CFG_SUBMODULE_OFFSET;

    /* set hwts tbu to bypass mode */
    NPU_REG_WRITE(NPU_TS_SUBSYS_BASE, SOC_NPU_HWTS_TBU_SUBMODULE_OFFSET + 0x1000, 0x09);

    /* request leave power-down mode, request leave clock-gating mode */
    NPU_REG_WRITE(smmu_tcu_cfg_base, SOC_SMMU_TCU_LP_REQ_OFFSET, 0x3);

    msleep(100); /* wait 100 ms for doing power on */
    NPU_DRV_PRINTF("smmu power-down request status : 0x%x", \
        NPU_REG_READ(smmu_tcu_cfg_base, SOC_SMMU_TCU_LP_ACK_OFFSET));

    /* global Control Register 0, bit0 : 0: disable smmu */
    NPU_REG_WRITE(smmu_tcu_cfg_base, SOC_SMMU_CR0_OFFSET, 0xc);

    NPU_DRV_PRINTF("smmu global status 0: 0x%x, expect 0xc.\n", \
        NPU_REG_READ(smmu_tcu_cfg_base, SOC_SMMU_CR0ACK_OFFSET));

    NPU_REG_WRITE(smmu_tcu_cfg_base, SOC_SMMU_S_CR0_OFFSET, 0xc);

    NPU_DRV_PRINTF("smmu secure global status 0: 0x%x, expect 0xc.\n", \
        NPU_REG_READ(smmu_tcu_cfg_base, SOC_SMMU_S_CR0ACK_OFFSET));

    /* AICORE tbu cfg */
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_AICORE_TBU_SUBMODULE_OFFSET, 0x8080e43);

    NPU_DRV_PRINTF("0x1f80004: 0x%x, expect 0xe03.\n", \
        NPU_REG_READ(NPU_CFG_BASE + SOC_NPU_AICORE_TBU_SUBMODULE_OFFSET, 0x4));
    return 0;
}
#else
static int npu_subsys_init(void)
{
    int   ret;
    unsigned int base;
    unsigned int reg;

   /****************tcu configure***************/
    base = NPU_CFG_BASE + SOC_SMMU_TCU_CFG_SUBMODULE_OFFSET;
    /* Request leave power-down mode */
    ret = npu_reg_bit_set_with_ack(base, SMMU_LP_REQ, SMMU_LP_ACK, TCU_QREQN_CG, TCU_QACCEPTN_CG);
    if (ret) {
        NPU_DRV_PRINTF("TCU_QACCEPTN_CG failed !%s\n", __func__);
        return -EINVAL;
    }
    /* Request leave clock-gating mode */
    ret = npu_reg_bit_set_with_ack(base, SMMU_LP_REQ, SMMU_LP_ACK, TCU_QREQN_PD, TCU_QACCEPTN_PD);
    if (ret) {
        NPU_DRV_PRINTF("TCU_QACCEPTN_PD failed !%s\n", __func__);
        return -EINVAL;
    }

    /****************tbu configure***************/
    // enable AICore tbu
    base = NPU_CFG_BASE + SOC_NPU_AICORE_TBU_SUBMODULE_OFFSET;
    /* enable TBU request */
    npu_reg_bit_set_with_ack(base, SMMU_TBU_CR, SMMU_TBU_CRACK, TBU_EN_REQ, TBU_EN_ACK);
    /* check TBU enable acknowledge */
    reg = NPU_REG_READ(base, SMMU_TBU_CRACK);
    if (!(reg & TBU_CONNECTED)) {
        NPU_DRV_PRINTF("%s:Fail to CONNECTE TBU failed!!!!!\n", __func__);
        return -EINVAL;
    }
    NPU_DRV_PRINTF("%s:AICORE TBU_CONNECTED!!!!!\n", __func__);

    /* set hwts tbu to bypass mode */
    NPU_REG_WRITE(NPU_TS_SUBSYS_BASE, SOC_NPU_HWTS_TBU_SUBMODULE_OFFSET + 0x1000, 0x09);
    NPU_REG64_WRITE(NPU_AICORE_BASE, 0x000078, 0x19101920);   // aicore unlock
    NPU_REG64_WRITE(NPU_AICORE_BASE, 0x000D48, 0x01);         // Configure no-secure aicore sid=1
    NPU_REG64_WRITE(NPU_AICORE_BASE, 0x000598, 0x00);         // Configure secure aicore sid=0

    return 0;
}
#endif

static void do_power_on_step1(void)
{
    unsigned int read_value;

    /* npu subsys, subsys crg, pericrg, adbmst reset. */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG188_OFFSET, 0xf);
    /* set gpio21 bit6 and bit7 output */
    read_value = NPU_REG_READ(0x00a65400, 0);
    NPU_REG_WRITE(0x00a65400, 0, (read_value | 0x40));
    /* set gpio21 bit6 and bit7 1 */
    NPU_REG_WRITE(0x00a65100, 0, 0x40);

    msleep(50); /* wait 50ms for doing power on */

    // step1.2,reset
    /* enable ssp0,1,2,3, esc clk select 100MHz, enable sci0/sci1 */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG347_OFFSET, 0xab5);
    /* bit 13: aicore reset */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG187_OFFSET, 0x40021ff);
    /* npu subsys, subsys crg, pericrg, adbmst unreset. */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG188_OFFSET, 0);
    /* cpm/pm unreset, pm clk select 200MHz, clk disable */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG461_OFFSET, 0);
}

static void do_power_on_step2(void)
{
    // step 2,clk en
    /* bit9: enable npu bus clk; bit10-11: npu bus clk div; bit12: enable npu bus clk,
       bit14: enable aicore clk, bit15:aicore clk select */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG187_OFFSET, 0x4007fff);
    /* bit0-2:aicore clk 355MHz, bit3-5: npu_div,355MHz,
       bit9-11: npu bus peri clk: 864MHz, bit12-14: npu_bus_cfg: 200M;
       bit15: enable aicore clk; bit16: enable npu_div; bit17: enable tscpu clk;
       bit18: enable npu bus per clk, bit19:enable npu bus cfg clk.
       bit20: enable npu dbg clk; bit21: enable npu adb mst clk;
       bit22: enable npu crg clk; bit23: enable npu cssys clk;
       bit24: enable npu tcx0 clk; bit25:enable npu monitor clk */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG186_OFFSET, 0x3ff8124);
    udelay(1); /* wait 1us for doing power on */
}

static void do_power_on_step3(void)
{
    // step 3,clk disable
    /* disable npu bus clk, disable aicore clk, aicore unreset */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG187_OFFSET, 0x40001ff);
    /* disable *** clk */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG186_OFFSET, 0x0);
    udelay(1); /* wait 1us for doing power on */
}

static void do_power_on_step4(void)
{
    // step 4 iso,mem repair
    /* disable npu powerdown isolate */
    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_NPU_PWRUP_CTRL_OFFSET, 0x0);
    /* disable cpu cluster1 powerdown isolate */
    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_CPU_PWRUP_CTRL_OFFSET, 0x0);
    udelay(400); /* wait 400us for doing isolate */
    /* disable pwm4 */
    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_PWM4_CTRL2_OFFSET, 0x0);
    /* set voltage of npu = 0.84V */
    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_PWM5_CTRL0_OFFSET, 0x4300DD);
    /* set voltage enable */
    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_PWM5_CTRL2_OFFSET, 0x1);
}

static void do_power_on_step6(void)
{
    // step 7,clk enable
    /* enable npu bus clk, enable aicore clk, aicore unreset */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG187_OFFSET, 0x4005fff);
     /* enable *** clk */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG186_OFFSET, 0x3ff8124);

    /* IPs clk enable control register0/register1/register2/register3 */
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_CRG_SUBMODULE_OFFSET + SOC_NPU_CRG_PEREN0_OFFSET, 0xffffffff);
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_CRG_SUBMODULE_OFFSET + SOC_NPU_CRG_PEREN1_OFFSET, 0xffffffff);
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_CRG_SUBMODULE_OFFSET + SOC_NPU_CRG_PEREN2_OFFSET, 0xffffffff);
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_CRG_SUBMODULE_OFFSET + SOC_NPU_CRG_PEREN3_OFFSET, 0xffffffff);
}

static void do_power_on_step7(void)
{
    // step 6 de-reset
    /* enable npu bus clk, enable aicore clk, aicore reset */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG187_OFFSET, 0x4007fff);
    /* npu subsys, subsys crg, pericrg, adbmst unreset. */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG188_OFFSET, 0);
    /* enable pm clk */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG461_OFFSET, 1);
    /* IPs unreset control register0/register1/register2 */
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_CRG_SUBMODULE_OFFSET + SOC_NPU_CRG_PERRSTDIS0_OFFSET, 0xffffffff);
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_CRG_SUBMODULE_OFFSET + SOC_NPU_CRG_PERRSTDIS1_OFFSET, 0xffffffff);
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_CRG_SUBMODULE_OFFSET + SOC_NPU_CRG_PERRSTDIS2_OFFSET, 0xffffffff);
}

static int do_power_on_step8(void)
{
    int readcount = 0;
    unsigned int readvalue;

    // setp 8 bus idle clear
    /* npu sys control register0, what it control ? */
    NPU_REG_WRITE(SYS_PERI_BASE, SOC_PERI_NPU_CTRL0_OFFSET, 0xf);

    readvalue = NPU_REG_READ(SYS_PERI_BASE, SOC_PERI_NPU_STAT0_OFFSET);
    while ((readvalue & SYS_PERI_NPU_STATUS0_SUCCESS) != SYS_PERI_NPU_STATUS0_SUCCESS) {
        NPU_REG_WRITE(SYS_PERI_BASE, SOC_PERI_NPU_CTRL0_OFFSET, 0x0);
        NPU_REG_WRITE(SYS_PERI_BASE, SOC_PERI_NPU_CTRL0_OFFSET, 0xf);
        udelay(1); /* wait 1 us delay per loop */
        readcount++;
        if (readcount > SYS_PERI_NPU_STATUS_WAIT_MAX_NUM) {
            NPU_DRV_PRINTF("npu sys control wait timeout!!\n");
            return -EFAULT;
        }
        readvalue = NPU_REG_READ(SYS_PERI_BASE, SOC_PERI_NPU_STAT0_OFFSET);
    }

    /* npu sys control register1, what it control ? */
    NPU_REG_WRITE(SYS_PERI_BASE, SOC_PERI_NPU_CTRL1_OFFSET, 0x0);

    readvalue = NPU_REG_READ(SYS_PERI_BASE, SOC_PERI_NPU_STAT1_OFFSET);
    readcount = 0;
    while ((readvalue & SYS_PERI_NPU_STATUS1_SUCCESS_MASK) != 0) {
        udelay(1); /* wait 1 us delay per loop */
        readcount++;
        if (readcount > SYS_PERI_NPU_STATUS_WAIT_MAX_NUM) {
            NPU_DRV_PRINTF("npu sys control wait timeout!!\n");
            return -EFAULT;
        }
        readvalue = NPU_REG_READ(SYS_PERI_BASE, SOC_PERI_NPU_STAT1_OFFSET);
    }
    return 0;
}

static void enable_hwts(void)
{
    /* enable db, hwts *** clk */
    NPU_REG_WRITE(NPU_TS_SUBSYS_BASE, SOC_TS_SYSCTRL_SUBMODULE_OFFSET + SOC_TS_SYSCTRL_PERIPHCTRL8_OFFSET, 0x1fff);
    /* enable db, hwts */
    NPU_REG_WRITE(NPU_TS_SUBSYS_BASE, SOC_TS_SYSCTRL_SUBMODULE_OFFSET + SOC_TS_SYSCTRL_PERIPHCTRL12_OFFSET, 0x1fff);
}

static void power_secure_cfg(void)
{
    /* easc */
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_EASC_CFG_SUBMODULE_OFFSET + 0x300, 0x1);  // easc_cfg0 unsafe
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_EASC_CFG_SUBMODULE_OFFSET + 0x1300, 0x1); // easc_cfg1 unsafe
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_EASC_CFG_SUBMODULE_OFFSET + 0x2300, 0x1); // easc_cfg2 unsafe
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_EASC_CFG_SUBMODULE_OFFSET + 0x3300, 0x1); // easc_cfg3 unsafe

    /* tzpc cfg unsafe */
    NPU_REG_WRITE(NPU_CFG_BASE, SOC_NPU_TZPC_SUBMODULE_OFFSET + 0x804, 0xffffffff);
}

int npu_drv_power_on(void)
{
    int ret;
    unsigned int regval, npu_min, volt_k;
    unsigned int license;
    unsigned int core_volt, core_pwm_value, hpm_value;

    ret = hi_tee_drv_get_license_support(HI_LICENSE_NPU_CAP, &license);
    if (ret < 0) {
        hi_log_dbg("get npu license failed\n");
        return -EFAULT;
    }
    if (license != 1) {
        hi_log_dbg("npu is unauthorized!\n");
        return -EFAULT;
    }

    NPU_DRV_PRINTF("npu power on begin.\n"); // board power on
    do_power_on_step1();
    do_power_on_step2();
    do_power_on_step3();
    do_power_on_step4();
    do_power_on_step6();
    do_power_on_step7();
    ret = do_power_on_step8();
    if (ret != 0) {
        NPU_DRV_PRINTF("fail to power on at step 8 \n");
        return -EFAULT;
    }

    hpm_value = get_npu_hpm();
    regval = NPU_REG_READ(SYS_CTL_BASE, SYS_CTRL_SC_GEN56_OFFSET);
    npu_min = regval & NPU_VMIN_BIT;
    volt_k = (regval >> 16) & NPU_VMIN_BIT; /* right shift 16 bits */
    core_volt = npu_min_value(NPU_VOLT_MAX, (npu_min - volt_k * hpm_value / NPU_VOLT_MAX));

    NPU_DRV_PRINTF("npu_min = %d, volt_k = %d\n", npu_min, volt_k);
    core_pwm_value = (((NPU_VOLT_MAX - core_volt) * PWM_CLASS * PWM_STEP_NUM) /
        (NPU_VOLT_MAX - NPU_VOLT_MIN)) * REGULATOR_OFFSET + REGULATOR_BASE;

    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_PWM5_CTRL0_OFFSET, core_pwm_value);
    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_PWM5_CTRL2_OFFSET, 0x1);

    enable_hwts();

    ret = npu_subsys_init();
    if (ret != 0) {
        NPU_DRV_PRINTF("fail to power on at subsys init \n");
        return -EFAULT;
    }

    power_secure_cfg();
    NPU_DRV_PRINTF("npu power on success!\n");
    return 0;
}

int hisi_npu_power_off(void)
{
    int readvalue = 0;
    int readcount = 0;

    while (readcount < SYS_PERI_NPU_STATUS_WAIT_MAX_NUM) {
        readvalue = NPU_REG_READ(SYS_PERI_BASE, SOC_PERI_NPU_STAT0_OFFSET);
        NPU_REG_WRITE(SYS_PERI_BASE, SOC_PERI_NPU_CTRL0_OFFSET, 0);
        readvalue = NPU_REG_READ(SYS_PERI_BASE, SOC_PERI_NPU_STAT0_OFFSET);
        if ((readvalue & SYS_PERI_NPU_STATUS0_SUCCESS) == 0) {
            break;
        } else {
            NPU_REG_WRITE(SYS_PERI_BASE, SOC_PERI_NPU_CTRL0_OFFSET, 0xf);
        }
        msleep(10);  /* wait 10 ms delay per loop */
        readcount++;
    }
    /* step2 nputop iso en */
    NPU_REG_WRITE(SYS_PMC_BASE, SOC_PMC_NPU_PWRUP_CTRL_OFFSET, 0x10000);
    /* step3 reset */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG188_OFFSET, 0xf);
    /* step 4 ck disable */
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG187_OFFSET, 0x40001ff);
    NPU_REG_WRITE(SYS_CRG_BASE, SOC_CRG186_OFFSET, 0x0);
    /* power down */
    NPU_REG_WRITE(0x00a65100, 0, 0x00); /* set gpio21 bit6 to 0 */

    NPU_DRV_PRINTF("npu power down success!\n");
    return 0;
}

