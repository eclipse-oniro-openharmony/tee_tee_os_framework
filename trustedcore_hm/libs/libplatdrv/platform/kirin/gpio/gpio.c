/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: provide GPIO access function interfaces.
 * Author: hisilicon
 * Create: 2019-08-7
 */

#include <gpio.h>
#include <mem_ops.h>
#include <drv_module.h>
#include "gpiomux.h"
#include "sre_access_control.h"
#include "sre_hwi.h"
#include "sre_syscalls_id_ext.h"
#include <hisi_boot.h>
#include <hisi_debug.h>
#include <soc_acpu_baseaddr_interface.h>
#include <secure_gic_common.h>
#include <tzpc.h>
#include "./../../kirin/include/hi_type.h"
#include <sys/usrsyscall_new_ext.h>
#include <sys/usrsyscall_ext.h>
#include <sys/hmapi_ext.h>
#include <hmlog.h>
#include "libdrv_frame.h"
#include "drv_param_type.h"

#if (TRUSTEDCORE_PLATFORM_CHOOSE == WITH_HIGENERIC_PLATFORM)

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
#include "gpiomux_define_hi3650.h"
#include "hi3650_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660)
#include "gpiomux_define_hi3660.h"
#include "hi3660_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#include "gpiomux_define_kirin970.h"
#include "kirin970_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6250)
#include "gpiomux_define_hi6250.h"
#include "hi6250_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#include "gpiomux_define_kirin710.h"
#include "kirin710_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW)
#include "gpiomux_define_miamicw.h"
#include "miamicw_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#include "gpiomux_define_kirin980.h"
#include "kirin980_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#if defined (WITH_KIRIN990_CS2)
#include "gpiomux_define_kirin990_cs2.h"
#include "kirin990_cs2_io_info.c"
#else
#include "gpiomux_define_kirin990.h"
#include "kirin990_io_info.c"
#endif

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#include "gpiomux_define_orlando.h"
#include "orlando_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#include "gpiomux_define_baltimore.h"
#include "baltimore_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#include "gpiomux_define_denver.h"
#include "denver_io_info.c"

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA)
#include "gpiomux_define_laguna.h"
#include "laguna_io_info.c"
#endif

#endif

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

/* define  maximum number in a group */
/*lint -e750 -esym(750,*)*/
#define GPIO_MAX_NUMBER 8
#define GPIO_GROUP_BIT 3
#define GPIO_REGISTER_OFFSET 2
#define GPIO_TEST_201 201
#define GPIO_TEST_202 202
/*lint -e750 +esym(750,*)*/

#define GPIO_MODE_MASK 0xFFFFFFF8
#define GPIO_PULL_MASK 0xFFFFFFFC
/*lint -e750 -esym(750,*)*/
#define GPIO_DRIVER_MASK 0XFFFFFFCF
#define GPIO_DRIVER_SPECIAL_MASK 0XFFFFFF8F
/*lint -e750 +esym(750,*)*/

/* define GPIO register offset address */
#define GPIODIR 0x400
#define GPIOIS 0x404
#define GPIOIBE 0x408
#define GPIOIEV 0x40C
#define GPIOIE 0x410
/*lint -e750 -esym(750,*)*/
#define GPIOIE2 0x500
#define GPIOIE3 0x504
#define GPIORIS 0x414
#define GPIOAFSEL 0x420
#define GPIODATA 0x3FC
/*lint -e750 +esym(750,*)*/
#define GPIOMIS 0x418
#define GPIOIC 0x41C
#define USR_SP_OFFSET (8)
#define GPIO_FIRST_BIT (0x1)
#define GPIO_IRQ_ENABLE_FLAG (0x1)

#define GPIO_TO_OFFSET(gpio) ((gpio) % 8)

#define RES0_LOCK_OFFSET 0x400
#define RES0_UNLOCK_OFFSET 0x404
#define RES0_LOCK_STAT_OFFSET 0x408

#define LOCK_CMD (0x1 << 4)
#define MASK_ID (0x7 << 5)
#define LOCK_VAL (MASK_ID | LOCK_CMD)
#define LOCK_ID_MASK (0xf << 4)

extern void irq_lock(void);
extern void irq_unlock(void);

/* define gpio_handler function */
typedef void (*handler_single)(void *);
typedef struct {
	unsigned int gpio_num;
	handler_single handler;
	void *driver_data;
} gpio_handler_group;

gpio_handler_group g_gpio_irq_handler_table[GPIO_HANDLER_NUM];

static int gpio_hwspin_lock(void)
{
	unsigned int val;
	int rc;
	rref_t ctrl_ref;

	ctrl_ref = get_sysctrl_hdlr();
	if (is_ref_err(ctrl_ref)) {
		hm_error("sys ctrl channel is not ready\n");
	} else {
		rc = hmex_disable_local_irq(ctrl_ref, hm_tcb_get_cref());
		if (rc)
			hm_error("hmex_disable_local_irq failed: %s\n", hmapi_strerror(rc));
	}

	do {
		hisi_writel(LOCK_VAL, REG_BASE_PCTRL + RES0_LOCK_OFFSET);
		val = hisi_readl(REG_BASE_PCTRL + RES0_LOCK_STAT_OFFSET);
	} while ((val & LOCK_ID_MASK) != LOCK_VAL);

	HISI_PRINT_DEBUG("gpio get hwspinlock succ\n");
	return 0;
}

static void gpio_hwspin_unlock(void)
{
	int rc;
	rref_t ctrl_ref;

	hisi_writel(LOCK_VAL, REG_BASE_PCTRL + RES0_UNLOCK_OFFSET);
	HISI_PRINT_DEBUG("gpio put hwspinlock succ, stat is 0x%x\n",
		LOCK_ID_MASK &
			hisi_readl(REG_BASE_PCTRL + RES0_LOCK_STAT_OFFSET));

	ctrl_ref = get_sysctrl_hdlr();
	if (is_ref_err(ctrl_ref)) {
		hm_error("sys ctrl channel is not ready\n");
		return;
	}

	rc = hmex_enable_local_irq(ctrl_ref, hm_tcb_get_cref());
	if (rc)
		hm_error("hmex_enable_local_irq failed: %s\n", hmapi_strerror(rc));

	return;
}

static int gpio_check_valid(unsigned int gpio_id)
{
	if (GPIO_TO_GROUP(gpio_id) > GPIO_MAX_GROUP) {
		return HI_FAILURE;
	} else {
		return 0;
	}
}

static gpio_io_info *gpio_find_io_info(unsigned int gpio_id)
{
	gpio_io_info *io_info_entry = NULL;
	int index = 0;

	/* check the gpio  */
	if (gpio_check_valid(gpio_id)) {
		HISI_PRINT_ERROR("[gpio]: gpio-%d is invalid, could not find "
				 "it's info\n",
			gpio_id);
		return NULL;
	}

	io_info_entry =
		(gpio_io_info *)(&(gpio_io_info_table[index])); /*lint !e838 */

	/* find gpio info in global list */
	while (INVALID_VALUE_GPIO != io_info_entry->gpio_id) {
		if (gpio_id == io_info_entry->gpio_id) {
			HISI_PRINT_DEBUG(
				"[gpio]find gpio-%d iocg and iomg!\n", gpio_id);
			return io_info_entry;
		}

		index++;
		io_info_entry = (gpio_io_info *)(&(gpio_io_info_table[index]));
	}

	return NULL;
}

/* get base address by group */
static inline unsigned int gpio_get_base(unsigned int gpio_group)
{
	return reg_base_gpio[gpio_group];
}

/* get base address by gpio number */
static inline unsigned int gpio_get_base_addr(unsigned int gpio_id)
{
	return gpio_get_base(GPIO_TO_GROUP(gpio_id));
}

static inline unsigned int gpio_get_tzpc_bit(unsigned int gpio_group)
{
	/* get tzpc bits of group */
	return gpio_tzpc_bits[gpio_group];
}

int gpio_set_sec(unsigned int gpio_id)
{
	/* check the gpio  */
	if (gpio_check_valid(gpio_id)) {
		HISI_PRINT_ERROR(
			"[gpio]: gpio-%d is invalid, could not request\n",
			gpio_id);
		return HI_FAILURE;
	}

	/* whether  supports secure config */
	if (GPIO_TO_GROUP(gpio_id) >= GPIO_SEC_NUM) {
		HISI_PRINT_ERROR(
			"[gpio]: gpio-%d could not support sec config\n",
			gpio_id);
		return 0;
	}

	return tzpc_cfg(gpio_get_tzpc_bit(GPIO_TO_GROUP(gpio_id)), TZPC_SEC);
}

void gpio_set_unsec(unsigned int gpio_id)
{
	/* check the gpio  */
	if (gpio_check_valid(gpio_id)) {
		HISI_PRINT_ERROR("[gpio]: gpio-%d is invalid, could not free\n",
			gpio_id);
		return;
	}

	/* whether  supports secure config */
	if (GPIO_TO_GROUP(gpio_id) >= GPIO_SEC_NUM) {
		HISI_PRINT_ERROR("[gpio]: gpio-%d needs not set non-sec mode\n",
			gpio_id);
		return;
	}

	tzpc_cfg(gpio_get_tzpc_bit(GPIO_TO_GROUP(gpio_id)), TZPC_UNSEC);

	return;
}

/* get direction */
unsigned int gpio_get_direction(unsigned int gpio_id)
{
	unsigned int gpio_base_addr, reg_value;

	if (gpio_check_valid(gpio_id)) {
		HISI_PRINT_ERROR(
			"[gpio]: gpio-%d is invalid\n",
			gpio_id);
		return GPIO_INVALID_VALUE_DIRECT;
	}

	gpio_base_addr = gpio_get_base_addr(gpio_id);
	reg_value = hisi_readl(gpio_base_addr + GPIODIR);

	return (reg_value >> GPIO_TO_OFFSET(gpio_id)) & GPIO_FIRST_BIT;
}

/* set the gpio to input */
void gpio_set_direction_input(unsigned int gpio_id)
{
	unsigned int gpio_base_addr, reg_value_old, reg_value_new;

	if (gpio_check_valid(gpio_id)) {
		HISI_PRINT_ERROR(
			"[gpio]: gpio-%d is invalid\n",
			gpio_id);
		return;
	}

	gpio_base_addr = gpio_get_base_addr(gpio_id);
	irq_lock();
	if (gpio_hwspin_lock()) {
		HISI_PRINT_ERROR("[gpio] gpio-%d could not set DI\n", gpio_id);
		irq_unlock();
		return;
	}

	reg_value_old = hisi_readl(gpio_base_addr + GPIODIR);
	reg_value_new = (~((unsigned int)GPIO_FIRST_BIT << GPIO_TO_OFFSET(gpio_id))) &
			(reg_value_old);
	hisi_writel(reg_value_new, gpio_base_addr + GPIODIR);

	gpio_hwspin_unlock();
	irq_unlock();

	return;
}

/* set the gpio to output */
void gpio_set_direction_output(unsigned int gpio_id)
{
	unsigned int gpio_base_addr, reg_value_old, reg_value_new;


	if (gpio_check_valid(gpio_id)) {
		HISI_PRINT_ERROR(
			"[gpio]: gpio-%d is invalid\n",
			gpio_id);
		return;
	}

	gpio_base_addr = gpio_get_base_addr(gpio_id);
	irq_lock();
	if (gpio_hwspin_lock()) {
		HISI_PRINT_ERROR("[gpio] gpio-%d could not set DO\n", gpio_id);
		irq_unlock();
		return;
	}

	reg_value_old = hisi_readl(gpio_base_addr + GPIODIR);
	reg_value_new = (((unsigned int)GPIO_FIRST_BIT << GPIO_TO_OFFSET(gpio_id))) |
			(reg_value_old);
	hisi_writel(reg_value_new, gpio_base_addr + GPIODIR);

	gpio_hwspin_unlock();
	irq_unlock();

	return;
}

/* get gpio value, HIGH or LOW ? */
unsigned int gpio_get_value(unsigned int gpio_id)
{
	unsigned int gpio_base_addr, gpio_data_reg, gpio_number;

	if (gpio_check_valid(gpio_id)) {
		HISI_PRINT_ERROR(
			"[gpio]: gpio-%d is invalid\n",
			gpio_id);
		return GPIO_INVALID_VALUE_DIRECT;
	}

	gpio_base_addr = gpio_get_base_addr(gpio_id);
	gpio_number = GPIO_TO_OFFSET(gpio_id);
	gpio_data_reg =
		((unsigned int)GPIO_FIRST_BIT << (gpio_number + GPIO_REGISTER_OFFSET));

	return hisi_readl(gpio_base_addr + gpio_data_reg) >> gpio_number;
}

/* set gpio value */
void gpio_set_value(unsigned int gpio_id, unsigned int expect_value)
{
	unsigned int gpio_base_addr, gpio_number, gpio_data_reg;

	if (gpio_check_valid(gpio_id)) {
		HISI_PRINT_ERROR(
			"[gpio]: gpio-%d is invalid\n",
			gpio_id);
		return;
	}

	gpio_base_addr = gpio_get_base_addr(gpio_id);
	gpio_number = GPIO_TO_OFFSET(gpio_id);
	gpio_data_reg =
		((unsigned int)GPIO_FIRST_BIT << (gpio_number + GPIO_REGISTER_OFFSET));

	hisi_writel(
		expect_value << gpio_number, gpio_base_addr + gpio_data_reg);

	return;
}

/* set gpio function */
void gpio_set_mode(unsigned int gpio_id, unsigned int expect_value)
{
	gpio_io_info *io_info_pointer;

	io_info_pointer = gpio_find_io_info(gpio_id);
	if ((NULL == io_info_pointer) ||
		(NO_IOMG == io_info_pointer->iomg_id)) {
		HISI_PRINT_ERROR(
			"[gpio] gpio-%d not find io info or iomg.\n", gpio_id);
		return;
	}

	hisi_writel((hisi_readl(io_info_pointer->iomg_id) & GPIO_MODE_MASK) |
			    expect_value,
		io_info_pointer->iomg_id);

	return;
}

/* get gpio function */
int gpio_get_mode(unsigned int gpio_id)
{
	gpio_io_info *io_info_pointer;

	io_info_pointer = gpio_find_io_info(gpio_id);
	if ((NULL == io_info_pointer) ||
		(NO_IOMG == io_info_pointer->iomg_id)) {
		HISI_PRINT_ERROR(
			"[gpio] gpio%d not find io info or iomg.\n", gpio_id);
		return HI_FAILURE;
	}

	return (int)(hisi_readl(io_info_pointer->iomg_id) & GPIO_MODE_MASK);
}

/* set pulltype */
void gpio_set_pull(unsigned int gpio_id, unsigned int expect_value)
{
	gpio_io_info *io_info_pointer;

	io_info_pointer = gpio_find_io_info(gpio_id);
	if ((NULL == io_info_pointer) ||
		(NO_IOMG == io_info_pointer->iomg_id)) {
		HISI_PRINT_ERROR(
			"[gpio] gpio-%d not find io info or iomg.\n", gpio_id);
		return;
	}

	hisi_writel((hisi_readl(io_info_pointer->iocg_id) & GPIO_PULL_MASK) |
			    expect_value,
		io_info_pointer->iocg_id);

	return;
}

/* set irq type of trigger */
static void gpio_irq_type(unsigned int gpio_id, unsigned int trigger)
{
	unsigned int gpio_base_addr, gpio_mask, gpioiev, gpiois, gpioibe;

	gpio_mask = BIT(GPIO_TO_OFFSET(gpio_id));
	gpio_base_addr = gpio_get_base_addr(gpio_id);

	irq_lock();
	if (gpio_hwspin_lock()) {
		HISI_PRINT_ERROR(
			"[gpio] gpio-%d could not set irq type\n", gpio_id);
		irq_unlock();
		return;
	}

	gpioiev = hisi_readl(gpio_base_addr + GPIOIEV);
	gpiois = hisi_readl(gpio_base_addr + GPIOIS);

	if ((trigger == IRQ_TYPE_LEVEL_HIGH) ||
		(trigger == IRQ_TYPE_LEVEL_LOW)) {
		gpiois |= gpio_mask;
		if (trigger == IRQ_TYPE_LEVEL_HIGH) {
			gpioiev |= gpio_mask;
		} else {
			gpioiev &= ~gpio_mask;
		}
	} else {
		gpioibe = hisi_readl(gpio_base_addr + GPIOIBE);
		gpiois &= ~gpio_mask;
		if (trigger == IRQ_TYPE_EDGE_RISING) {
			gpioibe &= ~gpio_mask;
			gpioiev |= gpio_mask;
		} else if (trigger == IRQ_TYPE_EDGE_FALLING) {
			gpioibe &= ~gpio_mask;
			gpioiev &= ~gpio_mask;
		} else {
			gpioibe |= gpio_mask;
		}

		hisi_writel(gpioibe, gpio_base_addr + GPIOIBE);
	}

	hisi_writel(gpiois, gpio_base_addr + GPIOIS);
	hisi_writel(gpioiev, gpio_base_addr + GPIOIEV);

	gpio_hwspin_unlock();
	irq_unlock();

	return;
}

static bool is_gpio_irq_registered(unsigned int gpio_id)
{
	int i;

	for (i = 0; i < GPIO_HANDLER_NUM; i++)
		if ((g_gpio_irq_handler_table[i].gpio_num == gpio_id) &&
			g_gpio_irq_handler_table[i].handler) {
			return true;
		}

	return false;
}

/* enable or disable irq */
void gpio_irq_ctrl(unsigned int gpio_id, unsigned int enable)
{
	unsigned int gpio_base_addr, gpio_mask, gpioie;

	if (false == is_gpio_irq_registered(gpio_id)) {
		HISI_PRINT_ERROR("[gpio] gpio-%d irq has not been registered\n",
			gpio_id);
		return;
	}

	gpio_mask = BIT(GPIO_TO_OFFSET(gpio_id));
	gpio_base_addr = gpio_get_base_addr(gpio_id);

	irq_lock();
	if (gpio_hwspin_lock()) {
		HISI_PRINT_ERROR("[gpio] gpio-%d could not ctrl(%d) irq\n",
			gpio_id, enable); /*lint !e515 */
		irq_unlock();
		return;
	}

	gpioie = hisi_readl(gpio_base_addr + GPIOIE);

	if (enable & GPIO_FIRST_BIT) {
		gpioie |= gpio_mask;
	} else {
		gpioie &= ~gpio_mask;
	}

	hisi_writel(gpioie, gpio_base_addr + GPIOIE);

	gpio_hwspin_unlock();
	irq_unlock();

	return;
}

/* get irq status */
static unsigned int gpio_irq_status(unsigned int gpio_id)
{
	unsigned int gpio_base_addr, gpio_number, status;

	gpio_number = GPIO_TO_OFFSET(gpio_id);

	gpio_base_addr = gpio_get_base_addr(gpio_id);
	status = hisi_readl(gpio_base_addr + GPIOMIS);

	return (status >> gpio_number) & GPIO_FIRST_BIT;
}

/* clear irq status */
static void gpio_clear_irq(unsigned int gpio_id)
{
	unsigned int gpio_base_addr, gpio_number;

	gpio_number = GPIO_TO_OFFSET(gpio_id);
	gpio_base_addr = gpio_get_base_addr(gpio_id);

	hisi_writel((unsigned int)GPIO_FIRST_BIT << gpio_number,
				gpio_base_addr + GPIOIC);

	return;
}

/* find a available space in global irq-list */
static int gpio_find_irq_available_space(unsigned int gpio_id)
{
	int i;
	int ret = HI_FAILURE;

	for (i = 0; i < GPIO_HANDLER_NUM; i++) {
		if (!g_gpio_irq_handler_table[i].gpio_num && (ret < 0)) {
			ret = i;
		}
		if ((g_gpio_irq_handler_table[i].gpio_num == gpio_id) &&
			g_gpio_irq_handler_table[i].handler) {
			HISI_PRINT_ERROR(
				"[gpio] gpio-%d irq has been registered\n",
				gpio_id);
			return HI_FAILURE;
		}
	}

	return ret;
}

/* gpio handle function */
static void gpio_handler(unsigned int reserve)
{
	unsigned int i, gpio;
	UNUSED(reserve);

	/* which gpio irq actived by searching for irq-list */
	for (i = 0; i < GPIO_HANDLER_NUM; i++) {
		gpio = g_gpio_irq_handler_table[i].gpio_num;
		if (gpio_irq_status(gpio)) {
			gpio_clear_irq(gpio);
			if (g_gpio_irq_handler_table[i].handler) {
				g_gpio_irq_handler_table[i].handler(
					g_gpio_irq_handler_table[i]
						.driver_data);
				HISI_PRINT_DEBUG(
					"[gpio] gpio-%d irq happened\n", gpio);
			} else {
				HISI_PRINT_DEBUG("[gpio] gpio-%d irq happened, "
						 "but no handler\n",
					gpio);
			}
		}
	}

	return;
} /*lint !e715*/

static void gpio_gic_set(unsigned int gpio_id, unsigned int ctrl)
{
	unsigned int irq;
	int ret;

	irq = gpio_get_irq_num(gpio_id);

	/* if ctrl is 1, then create a fiq function, and enable it
	    if 0 disable this fiq, delete fiq function. */
	if (ctrl) {
		ret = (int)SRE_HwiCreate(irq, 0x0, INT_SECURE, gpio_handler, 0);
		if (ret != 0) {
			HISI_PRINT_DEBUG("[gpio] SRE_HwiCreate error\n");
			return;
		}
		ret = (int)SRE_HwiEnable(irq);
		if (ret != 0) {
			HISI_PRINT_DEBUG("[gpio] SRE_HwiEnable error\n");
		}
	} else {
		ret = (int)SRE_HwiDisable(irq);
		if (ret != 0) {
			HISI_PRINT_DEBUG("[gpio] SRE_HwiDisable error\n");
			return;
		}
		ret = (int)SRE_HwiDelete(irq);
		if (ret != 0) {
			HISI_PRINT_DEBUG("[gpio] SRE_HwiDelete error\n");
		}
	}

	return;
}

static bool is_gpio_group_irq_registered(unsigned int gpio_id)
{
	unsigned int grp, grp_temp;
	int i;

	grp = GPIO_TO_GROUP(gpio_id);

	for (i = 0; i < GPIO_HANDLER_NUM; i++) {
		if (gpio_id == g_gpio_irq_handler_table[i].gpio_num) {
			continue;
		}
		grp_temp = GPIO_TO_GROUP(g_gpio_irq_handler_table[i].gpio_num);
		if (g_gpio_irq_handler_table[i].handler && (grp == grp_temp)) {
			return true;
		}
	}

	return false;
}

/* request irq */
int gpio_irq_request(unsigned int gpio_id, void (*handler)(void *),
	unsigned int irqflags, void *data)
{
	int cnt;

	if (gpio_check_valid(gpio_id)) {
		HISI_PRINT_ERROR(
			"[gpio]: gpio_irq_request gpio-%d is invalid\n",
			gpio_id);
		return HI_FAILURE;
	}
	/* finds available space in global irq-list to save this gpio irq
	 * handler */
	cnt = gpio_find_irq_available_space(gpio_id);
	if (cnt >= 0) {
		g_gpio_irq_handler_table[cnt].gpio_num = gpio_id;
		g_gpio_irq_handler_table[cnt].handler = handler;
		g_gpio_irq_handler_table[cnt].driver_data = data;
	} else {
		HISI_PRINT_ERROR(
			"[gpio]gpio-%d has not available irq space\n", gpio_id);
		return HI_FAILURE;
	}

	if (false == is_gpio_group_irq_registered(gpio_id)) {
		gpio_gic_set(gpio_id, GPIO_IRQ_ENABLE_FLAG); /* enable fiq */
	}

	/* firstly, clear this gpio's irq status */
	gpio_clear_irq(gpio_id);
	/* then, set the gpio's irq triggered type */
	gpio_irq_type(gpio_id, irqflags);
	/* finally, enable this irq */
	gpio_irq_ctrl(gpio_id, GPIO_IRQ_ENABLE_FLAG);

	return 0;
}

/* free irq */
void gpio_free_irq(unsigned int gpio_id)
{
	unsigned int i;

	for (i = 0; i < GPIO_HANDLER_NUM; i++) {
		if (gpio_id == g_gpio_irq_handler_table[i].gpio_num) {
			/* disable gpio irq, and register is IE */
			gpio_irq_ctrl(gpio_id, 0);
			/* delete the list-node */
			g_gpio_irq_handler_table[i].gpio_num = 0;
			g_gpio_irq_handler_table[i].handler = 0;
			if (g_gpio_irq_handler_table[i].driver_data) {
				SRE_MemFree(0, g_gpio_irq_handler_table[i]
						       .driver_data);
				g_gpio_irq_handler_table[i].driver_data = 0;
			}
			if (false == is_gpio_group_irq_registered(gpio_id)) {
				gpio_gic_set(gpio_id, 0); /* disable fiq */
			}
			break;
		}
	}

	return;
}

#ifdef GPIO_DEBUG

static unsigned int g_count_gpio;
static void gpio_drvier_test_func(void *priv)
{
	HISI_PRINT_ERROR("*******irq-cnt %d\n", g_count_gpio++);
}

int gpio_driver_test(void)
{
	unsigned gpio = GPIO_TEST_201;
	unsigned result;

	/* case begin ... */
	HISI_PRINT_ERROR("Gpio test begin\n");

	result = gpio_irq_request(gpio, gpio_drvier_test_func,
		IRQ_TYPE_EDGE_RISING | IRQ_TYPE_EDGE_FALLING, NULL);

	if (result) {
		return HI_FAILURE;
	} else {
		HISI_PRINT_ERROR("+++ gpio-%d irq request\n", gpio);
	}

	gpio = GPIO_TEST_202;
	result = gpio_irq_request(gpio, gpio_drvier_test_func,
		IRQ_TYPE_EDGE_RISING | IRQ_TYPE_EDGE_FALLING, NULL);

	if (result) {
		return HI_FAILURE;
	} else {
		HISI_PRINT_ERROR("--- gpio-%d irq request\n", gpio);
	}

	return 0;
}
#endif

int gpio_init(void)
{
	return 0;
}

int driver_dep_test_gpio(void)
{
	HISI_PRINT_ERROR("driver_dep_test ok\n");
	return 0;
}
#include <hmdrv_stub.h>
int gpio_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
	UNUSED(params);
	UNUSED(permissions);
	HANDLE_SYSCALL(swi_id) {
	default:
		return HI_FAILURE;
	}
	return 0; /*lint !e438*/
}
/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(gpio_driver, 0, 0, 0, TC_DRV_MODULE_INIT, gpio_init, NULL,
	gpio_syscall, NULL, NULL);
/*lint +e528 -esym(528,*)*/
