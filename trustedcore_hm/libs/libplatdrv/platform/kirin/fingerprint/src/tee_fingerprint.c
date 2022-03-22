/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: fingerprint driver
 * Author: zhangfengxi
 * Create: 2017-8-22
 */

#include "tee_fingerprint.h"
#include <stdio.h>
#include <global_ddr_map.h>
#include <iomcu_ddr_map.h>
#include <register_ops.h> /* writel */
#include <sre_debug.h> /* uart_printf */
#include <drv_mem.h> /* sre_mmap */
#include <mem_ops.h>
#include <drv_pal.h>
#include <drv_module.h>
#include <gpio.h>
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "sre_access_control.h"
#include "../../spi/spi.h"
#include "sre_sys.h"
#include "tzpc.h"
#include "tee_log.h" /* uart_printf_func */
#include "boot_sharedmem.h"
#include "securec.h"
#include <hmdrv_stub.h>

#define RAM_ADDR_FINGERPRINT_GPIO_RST       0x0
#define RAM_ADDR_FINGERPRINT_GPIO_CS        0x4
#define RAM_ADDR_FINGERPRINT_GPIO_IRQ       0x8
#define RAM_ADDR_FINGERPRINT_GPIO_MODULEID  0xC
#define RAM_ADDR_FINGERPRINT_GPIO_IRQ_NUM   0x10
#define RAM_ADDR_FINGERPRINT_SPI_FREQ       0x14
#define RAM_ADDR_FINGERPRINT_FPC2050        0x18
#define RAM_ADDR_FINGERPRINT_PRODUCT        0x1C
#define RAM_ADDR_FINGERPRINT_SPI_NUM        0x20
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#define RAM_ADDR_FINGERPRINT_GPIO_RST_UD     0x24
#define RAM_ADDR_FINGERPRINT_GPIO_CS_UD      0x28
#define RAM_ADDR_FINGERPRINT_GPIO_IRQ_UD     0x2C
#define RAM_ADDR_FINGERPRINT_GPIO_FLASH_RST_UD 0x30
#define RAM_ADDR_FINGERPRINT_GPIO_CLK_UD     0x34
#define RAM_ADDR_FINGERPRINT_DMA 0x38
#endif

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
// 29 means gpio group num, defined in bootable/bootloader/hilegacy/src/drivers/gpio/gpio-pl061/kirin970_io_info.c,
// 8 means how many gpios in one group
#define MAX_GPIO_NUM (29 * 8)
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
// 34 means gpio group num, defined in bootable/bootloader/hilegacy/src/drivers/gpio/gpio-pl061/kirin980_io_info.c,
// 8 means how many gpios in one group
#define MAX_GPIO_NUM (34 * 8)
#endif

#define COL     36
#define NEO     35
#define LAYA    47
#define TONY    50
#define ELLE    56
#define VOGUE   57
#define TAHITI  59
#define SEATTLE 65
#define BMH     79
#define JEF     80
#define JER     82
#define BLT     88
#define OCEAN   89
#define NOAH    90
#define JSC     93
#define BAR     94
#define ANG     95
#define JADE    98
#define FP_ADDR_CAST(type, addr) (type *)(uintptr_t)(addr)

// change the the address of TA to address of driver
#define fp_spi_read_check(type) do { \
    write_addr_fp = args[FP_PARA_FIRST]; \
    read_addr_fp  = args[FP_PARA_SECOND]; \
    ACCESS_CHECK_A64(write_addr_fp, sizeof(struct type)); \
    ACCESS_CHECK_A64(read_addr_fp, sizeof(struct type)); \
    ACCESS_READ_RIGHT_CHECK(write_addr_fp, sizeof(struct type)); \
    ACCESS_READ_RIGHT_CHECK(read_addr_fp, sizeof(struct type)); \
} while (0)

#define fp_access_check(type, member, member_size) \
    ACCESS_CHECK_A64(((struct type *)(uintptr_t)temp_addr_fp)->member, \
        ((struct type *)(uintptr_t)temp_addr_fp)->member_size)

#define fp_access_write_right_check(type, member, member_size) \
    ACCESS_WRITE_RIGHT_CHECK(((struct type *)(uintptr_t)temp_addr_fp)->member, \
        ((struct type *)(uintptr_t)temp_addr_fp)->member_size)

#define fp_spi_write_check_rx(type, rx) do { \
    if ((void *)(uintptr_t)(rx) != NULL) { \
        ACCESS_CHECK_A64(((struct type *)(uintptr_t)(rx))->reg_addr, ((struct type *)(uintptr_t)(rx))->reg_len); \
        ACCESS_WRITE_RIGHT_CHECK(((struct type *)(uintptr_t)(rx))->reg_addr, \
            ((struct type *)(uintptr_t)(rx))->reg_len); \
        ACCESS_CHECK_A64(((struct type *)(uintptr_t)(rx))->buf_addr, ((struct type *)(uintptr_t)(rx))->buf_len); \
        ACCESS_WRITE_RIGHT_CHECK(((struct type *)(uintptr_t)(rx))->buf_addr, \
            ((struct type *)(uintptr_t)(rx))->buf_len); \
    } \
} while (0)

#define fp_spi_check(type) do { \
    fp_spi_read_check(type); \
    fp_spi_write_check_rx(type, write_addr_fp); \
    fp_spi_write_check_rx(type, read_addr_fp); \
} while (0)

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#define RESET_PIN_GPIO_ADDR   0xFFF0F400
#define RESET_PIN_GPIO_OFFSET 3
#define IRQ_PIN_GPIO_ADDR     0xFFF11F04
#define CLERA_IRQ             0xfff0f41c
#elif(TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660)
#define RESET_PIN_GPIO_ADDR   0xFF3B4400
#define RESET_PIN_GPIO_OFFSET 5
#define IRQ_PIN_GPIO_ADDR     0xFFF1187C
#define CLERA_IRQ             0xfff0f41c
#elif(TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#define RESET_PIN_GPIO_ADDR   0xE8A0F400
#define RESET_PIN_GPIO_OFFSET 6
#define IRQ_PIN_GPIO_ADDR     0xFFF11F48
#define CLERA_IRQ             0xE8A0F41C
#else
#define RESET_PIN_GPIO_ADDR   0xE8A16400
#define RESET_PIN_GPIO_OFFSET 5
#define IRQ_PIN_GPIO_ADDR     0xFFF1185C
#define CLERA_IRQ             0xfff0f41c
#endif

#define FP_MAX_SPI_SPEED 5000000
#define GPIO_BASE_SIZE   0x80
#define FP_BITS_PER_WORD 8
#define FP_TRANSFER_FULL_NUM  2
#define FP_TRANSFER_HALF_NUM  1

#define FP_RET_SUCCESS   0
#define FP_RET_FAIL      (-1)

static unsigned int mutex_flag;

void spidev_cs_set(u32 control);
void driver_set_reset_pin_direction(unsigned int direction);
void driver_set_irq_pin_pull_type(unsigned int pull_type);

struct spi_config_chip chip_info = {
    .hierarchy = SSP_MASTER,
    .slave_tx_disable = true,
    .cs_control = spidev_cs_set,
};

struct spi_device fp_spi = {
    .max_speed_hz = FP_MAX_SPI_SPEED,
    .mode = SPI_MODE_0,
    .bits_per_word = FP_BITS_PER_WORD,
    .controller_data = &chip_info,
};

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
void spidev2_cs_set(u32 control);

struct spi_config_chip chip_dev2_info = {
    .hierarchy = SSP_MASTER,
    .slave_tx_disable = true,
    .cs_control = spidev2_cs_set,
};

struct spi_device spi_dev2 = {
    .max_speed_hz = FP_MAX_SPI_SPEED,
    .mode = SPI_MODE_0,
    .bits_per_word = FP_BITS_PER_WORD,
    .controller_data = &chip_dev2_info,
};
#endif

struct register_addr_fingerprint_gpio reg_addr_fp_gpio;
unsigned int spi_base_addr = REG_BASE_SPI0;

// FP_IMAGE_BASE = DDR_FP_IMAGE_BASE_AP(vendor\hisi\ap\platform\kirin980\iomcu_ddr_map.h)
// #define HISI_RESERVED_SENSORHUB_PHYMEM_BASE 0x11B00000(vendor\hisi\ap\platform\kirin980\global_ddr_map.h)
// such as:0x12080000 = 0x11B00000 + 0x580000
/* lint -e553 */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#define FP_IMAGE_BASE                                      0x20780000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#define FP_IMAGE_BASE                                      0x13E80000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#define FP_IMAGE_BASE                                      0x12080000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#define FP_IMAGE_BASE                                      0x14100000
#else
#define FP_IMAGE_BASE                                      DDR_FP_IMAGE_BASE_AP
#endif

#define SOC_ADDR_BASE_ADDR_FINGERHUB                      (FP_IMAGE_BASE)
#define SOC_ADDR_BASE_ADDR_FINGERHUB_SENSORHUB_DATA       (SOC_ADDR_BASE_ADDR_FINGERHUB + 0x20000)
#define SOC_ADDR_BASE_ADDR_FINGERHUB_CAC                  (SOC_ADDR_BASE_ADDR_FINGERHUB + 0x10000)

#define READ_CAC_IMAGE        1
#define READ_FALLBACK_IMAGE   0
#define READ_SENSORHUB_DATA   12
#define MAX_FINGERPRINT_DATA  65535

int get_fingerprint_gpio(void)
{
    char gpio_base[GPIO_BASE_SIZE] = {0};

    if (get_shared_mem_info(TEEOS_SHARED_MEM_FINGERPRINT, (unsigned int *)gpio_base, sizeof(gpio_base))) {
        uart_printf_func("map fingerprint_gpio_base failed\n");
        return -FPC_GPIO_INIT_ERROR;
    }

    reg_addr_fp_gpio.reg_addr_fp_reset = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_RST));
    uart_printf("IN function rst gpio = %d\n", reg_addr_fp_gpio.reg_addr_fp_reset);

    reg_addr_fp_gpio.reg_addr_fp_spi_cs = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_CS));
    uart_printf("IN function cs gpio = %d\n", reg_addr_fp_gpio.reg_addr_fp_spi_cs);

    reg_addr_fp_gpio.reg_addr_fp_irq = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_IRQ));
    uart_printf("IN function irq gpio = %d\n", reg_addr_fp_gpio.reg_addr_fp_irq);

    reg_addr_fp_gpio.reg_addr_fp_module_id = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_MODULEID));
    uart_printf("IN function moduleid gpio = %d\n", reg_addr_fp_gpio.reg_addr_fp_module_id);

    reg_addr_fp_gpio.reg_addr_fp_spi_freq = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_SPI_FREQ));
    if (reg_addr_fp_gpio.reg_addr_fp_spi_freq > 0 && reg_addr_fp_gpio.reg_addr_fp_spi_freq != FP_MAX_SPI_SPEED)
        fp_spi.max_speed_hz = reg_addr_fp_gpio.reg_addr_fp_spi_freq;
    uart_printf("IN function spi freq = %d\n", reg_addr_fp_gpio.reg_addr_fp_spi_freq);

    reg_addr_fp_gpio.reg_addr_fp_fpc2050 = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_FPC2050));
    uart_printf("IN function 2050 support = %d\n", reg_addr_fp_gpio.reg_addr_fp_fpc2050);

    reg_addr_fp_gpio.spi_num = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_SPI_NUM));
    uart_printf("IN function spi num = %d\n", reg_addr_fp_gpio.spi_num);

    reg_addr_fp_gpio.product_id = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_PRODUCT));
    uart_printf("IN function product id = %d\n", reg_addr_fp_gpio.product_id);

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
    reg_addr_fp_gpio.reg_addr_fp_reset_ud = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_RST_UD));
    uart_printf("IN function ud rst gpio = %d\n", reg_addr_fp_gpio.reg_addr_fp_reset_ud);

    reg_addr_fp_gpio.reg_addr_fp_spi_cs_ud = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_CS_UD));
    uart_printf("IN function ud cs gpio = %d\n", reg_addr_fp_gpio.reg_addr_fp_spi_cs_ud);

    reg_addr_fp_gpio.reg_addr_fp_irq_ud = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_IRQ_UD));
    uart_printf("IN function ud irq gpio = %d\n", reg_addr_fp_gpio.reg_addr_fp_irq_ud);

    reg_addr_fp_gpio.reg_addr_fp_flash_rst_ud = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_FLASH_RST_UD));
    uart_printf("IN function ud flash rst gpio = %d\n", reg_addr_fp_gpio.reg_addr_fp_flash_rst_ud);

    reg_addr_fp_gpio.reg_addr_fp_clk_ud = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_CLK_UD));
    uart_printf("IN function ud clk gpio = %u\n", reg_addr_fp_gpio.reg_addr_fp_clk_ud);
#endif

    return FP_RET_SUCCESS;
}

int get_spi_info(void)
{
    int error = FP_RET_SUCCESS;

    switch (reg_addr_fp_gpio.spi_num) {
    case 0:
        spi_base_addr = REG_BASE_SPI0;
        uart_printf("spi num used spi0\n");
        break;
    case 1:
        spi_base_addr = REG_BASE_SPI1;
        uart_printf("spi num used spi1\n");
        break;
    case 2:
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
        spi_base_addr = REG_BASE_SPI4;
        uart_printf("spi num used spi4\n");
#else
        spi_base_addr = REG_BASE_SPI2;
        uart_printf("spi num used spi2\n");
#endif
        if (reg_addr_fp_gpio.product_id == NEO || \
            reg_addr_fp_gpio.product_id == LAYA || \
            reg_addr_fp_gpio.product_id == TONY || \
            reg_addr_fp_gpio.product_id == ELLE || \
            reg_addr_fp_gpio.product_id == VOGUE || \
            reg_addr_fp_gpio.product_id == TAHITI || \
            reg_addr_fp_gpio.product_id == COL || \
            reg_addr_fp_gpio.product_id == SEATTLE) {
            spi_base_addr = REG_BASE_SPI2;
            uart_printf("the product spi num used spi2\n");
        }
        break;
    default:
        uart_printf_func("not find the spi num\n");
        error = FP_RET_FAIL;
        break;
    }

    return error;
}

#if !(TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
static unsigned int fp_get_shift(unsigned int value)
{
    unsigned int shift = 0;
    // get the shift value from the value (addr (bit0 ~ bit9))
    switch (value) {
    case 0x4:
        shift = 0;
        break;
    case 0x8:
        shift = 1;
        break;
    case 0x10:
        shift = 2;
        break;
    case 0x20:
        shift = 3;
        break;
    case 0x40:
        shift = 4;
        break;
    case 0x80:
        shift = 5;
        break;
    case 0x100:
        shift = 6;
        break;
    case 0x200:
        shift = 7;
        break;
    default:
        uart_printf_func("not find the shift\n");
        break;
    }
    return shift;
}
#endif

unsigned int get_gpio_irq(void)
{
    unsigned int reg;
    unsigned int addr = reg_addr_fp_gpio.reg_addr_fp_irq;

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)

    reg = gpio_get_value(addr);
#else
    unsigned int value;
    unsigned int shift;

    value = addr & 0x3ff; // mark bit0 ~ bit9

    shift = fp_get_shift(value);

    reg = ((readl(addr) >> shift) & 0x01);
#endif

    return reg;
}

unsigned int get_fpc2050(void)
{
    unsigned int reg = reg_addr_fp_gpio.reg_addr_fp_fpc2050;
    return reg;
}

void fpc_reset_ctr(u32 control)
{
    unsigned int addr = reg_addr_fp_gpio.reg_addr_fp_reset;

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
    gpio_set_value(addr, control);
#else
    unsigned int shift;
    unsigned int value;
    unsigned int reg;

    reg = readl(addr);

    value = addr - REG_BASE_GPIO7;
    value = value & 0x3ff; // mark bit0 ~ bit 9

    shift = fp_get_shift(value);

    if (control == (u32)GPIOMUX_LOW)
        writel((reg & (~(1 << shift))), addr); // clear the bit
    else
        writel((reg | (1 << shift)), addr); // set the bit
#endif
}

void spidev_cs_set(u32 control)
{
    unsigned int addr = reg_addr_fp_gpio.reg_addr_fp_spi_cs;

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
    gpio_set_value(addr, control);
#else
    unsigned int reg;
    unsigned int value;
    unsigned int shift;

    reg = readl(addr);

    value = addr & 0x3ff; // mark bit0 ~ bit 9

    shift = fp_get_shift(value);

    if (control == (u32)GPIOMUX_LOW)
        writel((reg & (~(1 << shift))), addr); // clear the bit
    else
        writel((reg | (1 << shift)), addr); // set the bit
#endif
}

void fingerprint_disable_irq(unsigned char status)
{
    uart_printf("irq = 0x%x\n", reg_addr_fp_gpio.reg_addr_fp_irq);
    uart_printf("irq gpio direction = %d\n", gpio_get_direction(reg_addr_fp_gpio.reg_addr_fp_irq));
    writel(0x1, CLERA_IRQ); // clear irq
    gpio_set_direction_output(reg_addr_fp_gpio.reg_addr_fp_irq);
    uart_printf("irq gpio direction = %d\n", gpio_get_direction(reg_addr_fp_gpio.reg_addr_fp_irq));
    gpio_set_value(reg_addr_fp_gpio.reg_addr_fp_irq, status);
}

void fingerprint_hardware_reset(unsigned char status)
{
    if (status == GPIOMUX_LOW)
        fpc_reset_ctr((u32)GPIOMUX_LOW);
    else
        fpc_reset_ctr((u32)GPIOMUX_HIGH);
}

int  fingerprint_init(void)
{
    int error = get_fingerprint_gpio();

    if (error)
        return error;
    error = get_spi_info();
    return error;
}

static u8 get_product_id(void)
{
    u8 id = reg_addr_fp_gpio.product_id;
    return id;
}

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
unsigned int fingerprint_dev2_get_irq_status(void)
{
    unsigned int addr = reg_addr_fp_gpio.reg_addr_fp_irq_ud;

    if (addr > MAX_GPIO_NUM) {
        uart_printf_func("[fingerprint_dev2_get_irq_status] invalid addr\n");
        return FP_RET_SUCCESS;
    }

    return gpio_get_value(addr);
}

void fingerprint_dev2_hardware_reset(u32 control)
{
    unsigned int addr = reg_addr_fp_gpio.reg_addr_fp_reset_ud;

    if (addr > MAX_GPIO_NUM) {
        uart_printf_func("[fingerprint_dev2_hardware_reset] invalid addr\n");
        return;
    }

    if (control == (u32)GPIOMUX_HIGH)
        gpio_set_value(addr, (u32)GPIOMUX_HIGH);
    else if (control == (u32)GPIOMUX_LOW)
        gpio_set_value(addr, (u32)GPIOMUX_LOW);
    else
        uart_printf_func("[fingerprint_dev2_hardware_reset] invalid parameter\n");
}

void fingerprint_dev2_set_clk_pin_value(u32 control)
{
    unsigned int addr = reg_addr_fp_gpio.reg_addr_fp_clk_ud;

    if (addr > MAX_GPIO_NUM) {
        uart_printf_func("[fingerprint_dev2_set_clk_pin_value] invalid addr\n");
        return;
    }

    gpio_set_direction_output(addr);

    if (control == (u32)GPIOMUX_HIGH)
        gpio_set_value(addr, (u32)GPIOMUX_HIGH);
    else if (control == (u32)GPIOMUX_LOW)
        gpio_set_value(addr, (u32)GPIOMUX_LOW);
    else
        uart_printf_func("[fingerprint_dev2_set_clk_pin_value] invalid parameter\n");
}

void spidev2_cs_set(u32 control)
{
    unsigned int addr = reg_addr_fp_gpio.reg_addr_fp_spi_cs_ud;

    if (addr > MAX_GPIO_NUM) {
        uart_printf_func("[spidev2_cs_set] invalid addr\n");
        return;
    }

    if (control == (u32)GPIOMUX_HIGH)
        gpio_set_value(addr, (u32)GPIOMUX_HIGH);
    else if (control == (u32)GPIOMUX_LOW)
        gpio_set_value(addr, (u32)GPIOMUX_LOW);
    else
        uart_printf_func("[spidev2_cs_set] invalid parameter\n");
}

static void fingerprint_dev2_flash_reset(u32 control)
{
    unsigned int addr = reg_addr_fp_gpio.reg_addr_fp_flash_rst_ud;

    if (addr > MAX_GPIO_NUM) {
        uart_printf_func("[fingerprint_dev2_flash_reset] invalid addr\n");
        return;
    }

    if (control == (u32)GPIOMUX_HIGH)
        gpio_set_value(addr, (u32)GPIOMUX_HIGH);
    else if (control == (u32)GPIOMUX_LOW)
        gpio_set_value(addr, (u32)GPIOMUX_LOW);
    else
        uart_printf_func("[fingerprint_dev2_flash_reset] invalid parameter\n");
}
#endif

int  fingerprint_pc_pin_init(struct fp_cmd_info *command_info)
{
    int error;
    reg_addr_fp_gpio.reg_addr_fp_spi_cs = command_info->fp_spi_cs;
    reg_addr_fp_gpio.reg_addr_fp_irq = command_info->fp_irq_pin;
    reg_addr_fp_gpio.spi_num = command_info->fp_spi_num;

    gpio_set_mode(reg_addr_fp_gpio.reg_addr_fp_spi_cs, 0);
    gpio_set_direction_output(reg_addr_fp_gpio.reg_addr_fp_spi_cs);
    gpio_set_value(reg_addr_fp_gpio.reg_addr_fp_spi_cs, 1);
    gpio_set_mode(reg_addr_fp_gpio.reg_addr_fp_irq, 0);
    gpio_set_direction_input(reg_addr_fp_gpio.reg_addr_fp_irq);
    uart_printf_func(".spi_num = %d .reg_addr_fp_irq = %d .reg_addr_fp_spi_cs =%d\n", reg_addr_fp_gpio.spi_num, reg_addr_fp_gpio.reg_addr_fp_irq, reg_addr_fp_gpio.reg_addr_fp_spi_cs);
    error = get_spi_info();
    return error;
}

int32_t sensorhub_touch_data[3]; // the data length get from sensorhub is 3
int driver_fingerprint_command(struct fp_cmd_info *command_info)
{
    int error = FP_RET_SUCCESS;

    if (!command_info)
        return FP_RET_FAIL;

    switch (command_info->command) {
    case FINGERPRINT_SPI_INIT:
        error = fingerprint_init();
        break;
    case FINGERPRINT_READ_INT_STATUS:
        command_info->irq_pin_value = get_gpio_irq();
        break;
    case FINGERPRINT_RESET_SENSOR:
        fingerprint_hardware_reset(command_info->reset_pin_value);
        break;
    case FINGERPRINT_READ_MODULE_STATUS:
        command_info->module_value = get_fpc2050();
        break;
    case FINGERPRINT_GET_PRODUCT_INFO:
        command_info->product_value = get_product_id();
        break;
    case FINGERPRINT_GET_SENSORHUB_CAC_IMG:
        error = driver_read_image_from_sensorhub(FP_ADDR_CAST(uint8_t, command_info->sh_img_buf),
            command_info->sh_img_size, command_info->sh_shared_mem_addr_offset, READ_CAC_IMAGE);
        command_info->sh_anti_touch_cnt = sensorhub_touch_data[0];
        command_info->sh_fail_img_cnt = sensorhub_touch_data[1];
        break;
    case FINGERPRINT_GET_SENSORHUB_FALLBACK_IMG:
        error = driver_read_image_from_sensorhub(FP_ADDR_CAST(uint8_t, command_info->sh_img_buf),
            command_info->sh_img_size, command_info->sh_shared_mem_addr_offset, READ_FALLBACK_IMAGE);
        break;
    case FINGERPRINT_SET_RESET_PIN_DIRECTION:
        driver_set_reset_pin_direction(command_info->reset_pin_direction);
        break;
    case FINGERPRINT_SET_IRQ_PIN_PULLTYPE:
        driver_set_irq_pin_pull_type(command_info->irq_pin_pull_type);
        break;
    case FINGERPRINT_DISABLE_IRQ:
        uart_printf_func("fingerprint_command irqPinValue =%d\n", command_info->irq_pin_value);
        fingerprint_disable_irq(command_info->irq_pin_value);
        break;
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
    case FINGERPRINT_DEV2_READ_INT_STATUS:
        command_info->irq_pin_value = fingerprint_dev2_get_irq_status();
        break;
    case FINGERPRINT_DEV2_RESET_SENSOR:
        fingerprint_dev2_hardware_reset(command_info->reset_pin_value);
        break;
    case FINGERPRINT_DEV2_RESET_FLASH:
        fingerprint_dev2_flash_reset(command_info->reset_pin_value);
        break;
    case FINGERPRINT_DEV2_SET_CLK_PIN_VALUE:
        fingerprint_dev2_set_clk_pin_value(command_info->clk_pin_value);
        break;
#endif

    case FINGERPRINT_PC_PIN_INIT:
        error = fingerprint_pc_pin_init(command_info);
        break;
    default:
        error = FP_RET_FAIL;
        break;
    }

    return error;
}

void driver_set_reset_pin_direction(unsigned int direction)
{
    unsigned int reset_gpio_addr = RESET_PIN_GPIO_ADDR;
    unsigned int offset = RESET_PIN_GPIO_OFFSET;

    if (direction)
        writel((0x1 << offset) | readl(reset_gpio_addr), reset_gpio_addr); // set to output
    else
        writel((~(0x1 << offset)) & readl(reset_gpio_addr), reset_gpio_addr); // set to input
}

void driver_set_irq_pin_pull_type(unsigned int pull_type)
{
    // 0x0: NP; 0x1: PU; 0x2: PD
    if (pull_type > 0x2)
        return;
    writel(pull_type, IRQ_PIN_GPIO_ADDR);
}

int driver_read_image_from_sensorhub(uint8_t *image_buf, uint32_t image_size, uint32_t addr_offset, uint8_t image_type)
{
    uint32_t tmp_src_addr = 0;
    uint32_t tmp_src_addr_cac = 0;
    uint32_t tmp_src_sensorhub_data = 0;
    int ret;

    if (image_buf == NULL)
        return -EFAULT;
    if (image_size > MAX_FINGERPRINT_DATA)
        image_size = MAX_FINGERPRINT_DATA;
    if (image_type == READ_CAC_IMAGE) {
        if (sre_mmap(SOC_ADDR_BASE_ADDR_FINGERHUB_CAC, image_size, &tmp_src_addr_cac, secure, cache)) {
            uart_printf_func("map data buffer addr=0x%x error3\n", SOC_ADDR_BASE_ADDR_FINGERHUB_CAC);
            return -FPC_GPIO_INIT_ERROR;
        }
        ret = memcpy_s(image_buf, image_size, (uint8_t *)tmp_src_addr_cac, image_size);
        if (ret != EOK) {
            uart_printf_func("read_image_from_sensorhub memcpy_s fail %d\n", ret);
            return -EFAULT;
        }
        if (sre_unmap(tmp_src_addr_cac, image_size)) {
            uart_printf_func("unmap SOC_ADDR_BASE_ADDR_FINGERHUB failed\n");
            return -FPC_GPIO_INIT_ERROR;
        }
        if (sre_mmap(SOC_ADDR_BASE_ADDR_FINGERHUB_SENSORHUB_DATA, READ_SENSORHUB_DATA,
            &tmp_src_sensorhub_data, secure, cache)) {
            uart_printf_func("sre_mmap addr=0x%x error3\n", SOC_ADDR_BASE_ADDR_FINGERHUB_SENSORHUB_DATA);
            return -FPC_GPIO_INIT_ERROR;
        }
        ret = memcpy_s(&sensorhub_touch_data[0], READ_SENSORHUB_DATA,
            (uint8_t *)tmp_src_sensorhub_data, READ_SENSORHUB_DATA);
        if (ret != EOK) {
            uart_printf_func("read_image_from_sensorhub memcpy_s fail %d\n", ret);
            return -EFAULT;
        }

        if (sre_unmap(tmp_src_sensorhub_data, READ_SENSORHUB_DATA)) {
            uart_printf_func("unmap SOC_ADDR_BASE_ADDR_FINGERHUB failed\n");
            return -FPC_GPIO_INIT_ERROR;
        }
    } else {
        if (sre_mmap(SOC_ADDR_BASE_ADDR_FINGERHUB + addr_offset, image_size, &tmp_src_addr, secure, cache)) {
            uart_printf_func("sre_mmap addr=0x%x error3\n", SOC_ADDR_BASE_ADDR_FINGERHUB + addr_offset);
            return -FPC_GPIO_INIT_ERROR;
        }
        ret = memcpy_s(image_buf, image_size, (uint8_t *)tmp_src_addr, image_size);
        if (ret != EOK) {
            uart_printf_func("read_image_from_sensorhub memcpy_s fail %d\n", ret);
            return -EFAULT;
        }
        if (sre_unmap(tmp_src_addr, image_size)) {
            uart_printf_func("unmap SOC_ADDR_BASE_ADDR_FINGERHUB failed\n");
            return -FPC_GPIO_INIT_ERROR;
        }
    }

    return FP_RET_SUCCESS;
}
static int fp_spi_driver(
    struct spi_transaction_info *write_info, struct spi_transaction_info *read_info, struct spi_device *spi_set)
{
    struct spi_message msg = {0};
    struct spi_transfer xfers[FP_TRANSFER_FULL_NUM]; // include write and read data
    int ret;

    xfers[0].cs_change = false;
    xfers[0].delay_usecs = 0;
    xfers[0].tx_buf = FP_ADDR_CAST(void, write_info->reg_addr);
    xfers[0].rx_buf = NULL;
    xfers[0].len    = write_info->reg_len;

    if (read_info != NULL) {
        xfers[1].cs_change = true;
        xfers[1].delay_usecs = 0;
        xfers[1].tx_buf = NULL;
        xfers[1].rx_buf = FP_ADDR_CAST(void, read_info->buf_addr);
        xfers[1].len    = read_info->buf_len;
        msg.transfers = xfers;
        msg.transfer_num = FP_TRANSFER_FULL_NUM;
    } else if (FP_ADDR_CAST(void, write_info->buf_addr) != NULL) {
        xfers[1].cs_change = true;
        xfers[1].delay_usecs = 0;
        xfers[1].tx_buf = FP_ADDR_CAST(void, write_info->buf_addr);
        xfers[1].rx_buf = NULL;
        xfers[1].len    = write_info->buf_len;
        msg.transfers = xfers;
        msg.transfer_num = FP_TRANSFER_FULL_NUM;
    } else {
        xfers[0].cs_change = true;
        xfers[0].delay_usecs = 0;
        xfers[0].tx_buf = FP_ADDR_CAST(void, write_info->reg_addr);
        xfers[0].rx_buf = NULL;
        xfers[0].len    = write_info->reg_len;
        msg.transfers = xfers;
        msg.transfer_num = FP_TRANSFER_HALF_NUM;
    }

    mutex_flag = true;
    ret = hisi_spi_init(spi_base_addr, spi_set);
    if (ret != FP_RET_SUCCESS) {
        mutex_flag = false;
        return FP_RET_FAIL;
    }
    hisi_spi_polling_transfer(spi_base_addr, &msg);
    hisi_spi_exit(spi_base_addr);
    mutex_flag = false;

    return msg.status;
}
int driver_spi_full_duplex(struct spi_transaction_info *write_info, struct spi_transaction_info *read_info)
{
    if (write_info == NULL)
        return -EFAULT;
    return fp_spi_driver(write_info, read_info, &fp_spi);
}

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#define FP_DMA_SIZE (256 * 1024 + 10)
static uint8_t *dma_test;
extern void *malloc_coherent(size_t n);
static int fingerprint_dma_init(void)
{
    size_t sz = FP_DMA_SIZE;
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    unsigned char gpio_base[GPIO_BASE_SIZE] = {0};
    int ret;

    if (get_shared_mem_info(TEEOS_SHARED_MEM_FINGERPRINT, (unsigned int *)gpio_base, sizeof(gpio_base))) {
        uart_printf_func("get fingerprint gpio_base failed\n");
        return FP_RET_FAIL;
    }
    reg_addr_fp_gpio.dma_enable = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_DMA));
    uart_printf_func("fingerprint-dma enable = %u\n", reg_addr_fp_gpio.dma_enable);

    if (!reg_addr_fp_gpio.dma_enable)
        return FP_RET_SUCCESS;

    ret = sre_mmap(HISI_RESERVED_FINGERPRINT_BASE, sz, (uintptr_t *)(&dma_test), secure, non_cache);
    if (ret != FP_RET_SUCCESS) {
        uart_printf_func("%s:sre_mmap addr=0x%x error, ret=%d\n", __func__, HISI_RESERVED_FINGERPRINT_BASE, ret);
        return FP_RET_FAIL;
    }
#else
    dma_test = malloc_coherent(sz);
#endif
    if (dma_test == NULL) {
        tloge("%s: fail to malloc dma_test\n", __func__);
        return FP_RET_FAIL;
    }
    return memset_s(dma_test, sz, 0, sz);
}
#else
static int fingerprint_dma_init(void)
{
    return FP_RET_SUCCESS;
}
#endif

int driver_spi_full_duplex_with_speed(
    struct spi_transaction_info *write_info, struct spi_transaction_info *read_info, int speed)
{
    struct spi_message msg = {0};
    struct spi_transfer xfers;
    int ret;
    struct spi_device spi_set = {
        .max_speed_hz = speed,
        .mode = SPI_MODE_0,
        .bits_per_word = FP_BITS_PER_WORD,
        .controller_data = &chip_info,
    };

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
    if (dma_test == NULL)
        return FP_RET_FAIL;
#endif

    if (write_info == NULL) {
        xfers.tx_buf = NULL;
        if (read_info == NULL) {
            xfers.rx_buf = NULL;
        } else {
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
            if (reg_addr_fp_gpio.product_id == COL) // COL
                xfers.rx_buf = dma_test;
            else
                xfers.rx_buf = FP_ADDR_CAST(void, read_info->buf_addr);
#else
            xfers.rx_buf = FP_ADDR_CAST(void, read_info->buf_addr);
#endif
            xfers.len = read_info->buf_len;
        }
    }
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
    else {
        if (read_info == NULL) {
            xfers.rx_buf = NULL;
        } else {
            if (reg_addr_fp_gpio.product_id == COL) // COL
                xfers.rx_buf = dma_test;
            else
                xfers.rx_buf = FP_ADDR_CAST(void, read_info->buf_addr);
        }

        if (reg_addr_fp_gpio.product_id == COL) { // COL
            xfers.tx_buf = dma_test;
            if (memcpy_s(dma_test, FP_DMA_SIZE, write_info->buf_addr, write_info->buf_len) != EOK)
                uart_printf_func("memcpy_s to dma_test fail\n");
        } else {
            xfers.tx_buf = FP_ADDR_CAST(void, write_info->buf_addr);
        }
        xfers.len = write_info->buf_len;
    }
#else
    else {
        if (read_info == NULL)
            xfers.rx_buf = NULL;
        else
            xfers.rx_buf = FP_ADDR_CAST(void, read_info->buf_addr);
        xfers.tx_buf = FP_ADDR_CAST(void, write_info->buf_addr);
        xfers.len = write_info->buf_len;
    }
#endif

    xfers.cs_change = true;
    xfers.delay_usecs = 0;
    msg.transfers = &xfers;
    msg.transfer_num = FP_TRANSFER_HALF_NUM;

    mutex_flag = true;
    ret = hisi_spi_init(spi_base_addr, &spi_set);
    if (ret != FP_RET_SUCCESS) {
        mutex_flag = false;
        return FP_RET_FAIL;
    }
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
    if (reg_addr_fp_gpio.product_id == COL) // COL
        hisi_spi_dma_transfer(spi_base_addr, &msg);
    else
        hisi_spi_polling_transfer(spi_base_addr, &msg);
#else
    hisi_spi_polling_transfer(spi_base_addr, &msg);
#endif
    hisi_spi_exit(spi_base_addr);

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
    if (reg_addr_fp_gpio.product_id == COL && read_info) // COL
        if (memcpy_s(read_info->buf_addr, read_info->buf_len, dma_test, read_info->buf_len) != EOK)
            uart_printf_func("memcpy_s to read_info->buf_addr fail\n");
#endif

    mutex_flag = false;

    return msg.status;
}

int driver_spi_half_duplex_with_speed(
    struct spi_transaction_info *write_info, struct spi_transaction_info *read_info, int speed)
{
    struct spi_device spi_set = {
        .max_speed_hz = speed,
        .mode = SPI_MODE_0,
        .bits_per_word = FP_BITS_PER_WORD,
        .controller_data = &chip_info,
    };

    if (write_info == NULL)
        return -EFAULT;
    return fp_spi_driver(write_info, read_info, &spi_set);
}

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
int driver_spi_dev2_full_duplex(struct spi_transaction_info *write_info, struct spi_transaction_info *read_info)
{
    uart_printf("driver_spi_dev2_full_duplex in %d\n", reg_addr_fp_gpio.reg_addr_fp_spi_cs_ud);

    if ((!write_info) || (reg_addr_fp_gpio.reg_addr_fp_spi_cs_ud > MAX_GPIO_NUM))
        return -EFAULT;

    return fp_spi_driver(write_info, read_info, &spi_dev2);
}

#define MAX_TRANSFER_LEN        0x40000 // 256K
#define INVALID_TRANSFER_CNT    0xFFFF
#define HALF_DUPLEX_BASE_CNT    1

static unsigned int g_former_spi_support[] = {
    NEO,
    COL,
    LAYA,
    TONY,
    ELLE,
    VOGUE,
    BMH,
    JEF,
    JER,
    BLT,
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    OCEAN,
#endif
    NOAH,
    JSC,
    ANG,
    BAR,
    JADE,
};

static u8 g_spi_mode = SPI_MODE_0;

static int fp_set_spi_mode(unsigned int mode)
{
    int ret = FP_RET_SUCCESS;

    switch (mode) {
    case SPI_MODE_0:
    case SPI_MODE_1:
    case SPI_MODE_2:
    case SPI_MODE_3:
        g_spi_mode = (u8)mode;
        break;
    default:
        ret = FP_RET_FAIL;
        uart_printf_func("fp_set_spi_mode fail: %u\n", mode);
        break;
    }

    return ret;
}

static bool fp_check_return(unsigned int *arry, int arry_len, unsigned int flag)
{
    int i;
    bool status = false;

    if (arry == NULL)
        return false;

    for (i = 0; i < arry_len; i++) {
        if (arry[i] == flag) {
            status = true;
            break;
        }
    }
    return status;
}

static unsigned int spi_dev2_duplex_comm_get_cnt(const struct spi_transaction_info *write_info,
    const struct spi_transaction_info *read_info, unsigned int *total_len)
{
    unsigned int transfer_cnt;

    if (FP_ADDR_CAST(void, write_info->buf_addr))
        *total_len = write_info->buf_len;
    else if (read_info)
        *total_len = read_info->buf_len;

    if (*total_len > FP_DMA_SIZE)
        return INVALID_TRANSFER_CNT;

    transfer_cnt = *total_len / MAX_TRANSFER_LEN;
    if ((*total_len % MAX_TRANSFER_LEN) != 0)
        transfer_cnt += 1;

    return transfer_cnt;
}

static inline void spi_dev2_duplex_comm_get_joint_data_setup(
    struct spi_transfer *transfers, unsigned int *total_len, unsigned int *offset, unsigned int index)
{
    unsigned int transfer_len = (*total_len <= MAX_TRANSFER_LEN) ? *total_len : MAX_TRANSFER_LEN;

    transfers[index].len = transfer_len;
    transfers[index].cs_change = false;
    transfers[index].delay_usecs = 0;
    *total_len -= transfer_len;
    *offset += transfer_len;
}

static void spi_dev2_full_duplex_comm_get_joint_data(struct spi_transfer *transfers, unsigned char *dma_buffer,
    unsigned int total_len, unsigned int transfer_cnt)
{
    unsigned int i = 0;
    unsigned int offset = 0;

    for (; i < transfer_cnt; i++) {
        transfers[i].tx_buf = dma_buffer + offset;
        transfers[i].rx_buf = dma_buffer + offset;

        spi_dev2_duplex_comm_get_joint_data_setup(transfers, &total_len, &offset, i);
    }
    transfers[transfer_cnt - 1].cs_change = true;
}

static inline int spi_dev2_duplex_comm_transfer_with_speed_setup(
    struct spi_transfer *transfers, struct spi_message *msg, unsigned int transfer_cnt, int speed)
{
    struct spi_device spi_set = {
        .max_speed_hz = speed,
        .mode = g_spi_mode,
        .bits_per_word = FP_BITS_PER_WORD,
        .controller_data = &chip_dev2_info,
    };
    msg->transfers = transfers;
    msg->transfer_num = transfer_cnt;
    return hisi_spi_init(spi_base_addr, &spi_set);
}

static int spi_dev2_full_duplex_comm_transfer_with_speed(struct spi_transfer *transfers,
    unsigned int transfer_cnt, int speed)
{
    int ret;
    struct spi_message msg;
    (void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));

    ret = spi_dev2_duplex_comm_transfer_with_speed_setup(transfers, &msg, transfer_cnt, speed);
    if (ret != SPI_OK) {
        uart_printf_func("spi_dev2_duplex_comm_transfer_with_speed_setup failed, ret = %d\n", ret);
        return -EFAULT;
    }

    ret = hisi_spi_dma_transfer(spi_base_addr, &msg);
    if (ret != SPI_OK) {
        uart_printf_func("hisi_spi_dma_transfer failed, ret = %d\n", ret);
        msg.status = -EFAULT;
    }

    hisi_spi_exit(spi_base_addr);
    return msg.status;
}

static int driver_spi_dev2_full_duplex_with_speed_former(struct spi_transaction_info *write_info,
    struct spi_transaction_info *read_info, int speed)
{
    struct spi_message msg = {0};
    struct spi_transfer xfers;
    int ret;
    struct spi_device spi_set = {
        .max_speed_hz = speed,
        .mode = g_spi_mode,
        .bits_per_word = FP_BITS_PER_WORD,
        .controller_data = &chip_dev2_info,
    };

    if (dma_test == NULL)
        return FP_RET_FAIL;

    if (write_info == NULL) {
        xfers.tx_buf = NULL;
        if (read_info == NULL) {
            xfers.rx_buf = NULL;
        } else {
            xfers.rx_buf = dma_test;
            xfers.len = read_info->buf_len;
        }
    } else {
        if (read_info == NULL)
            xfers.rx_buf = NULL;
        else
            xfers.rx_buf = dma_test;

        xfers.tx_buf = dma_test;
        ret = memcpy_s(dma_test, FP_DMA_SIZE, FP_ADDR_CAST(void, write_info->buf_addr), write_info->buf_len);
        if (ret != EOK)
            return FP_RET_FAIL;
        xfers.len = write_info->buf_len;
    }

    xfers.cs_change = true;
    xfers.delay_usecs = 0;
    msg.transfers = &xfers;
    msg.transfer_num = FP_TRANSFER_HALF_NUM;

    mutex_flag = true;
    ret = hisi_spi_init(spi_base_addr, &spi_set);
    if (ret != FP_RET_SUCCESS) {
        mutex_flag = false;
        return FP_RET_FAIL;
    }

    hisi_spi_dma_transfer(spi_base_addr, &msg);
    hisi_spi_exit(spi_base_addr);
    if (read_info != NULL && read_info->buf_len != 0 && FP_ADDR_CAST(void, read_info->buf_addr) != NULL) {
        ret = memcpy_s(FP_ADDR_CAST(void, read_info->buf_addr), read_info->buf_len, dma_test, read_info->buf_len);
        if (ret != EOK) {
            mutex_flag = false;
            return FP_RET_FAIL;
        }
    }
    mutex_flag = false;

    return msg.status;
}

int driver_spi_dev2_full_duplex_with_speed(struct spi_transaction_info *write_info,
    struct spi_transaction_info *read_info, int speed)
{
    int ret = FP_RET_FAIL;
    struct spi_transfer *transfers = NULL;
    unsigned int total_len = 0;
    unsigned int transfer_cnt;
    unsigned char *dma_buffer = NULL;

    if (fp_check_return(g_former_spi_support, ARRAY_SIZE(g_former_spi_support), reg_addr_fp_gpio.product_id)) {
        ret = driver_spi_dev2_full_duplex_with_speed_former(write_info, read_info, speed);
        if (ret != FP_RET_SUCCESS)
            uart_printf_func("driver_spi_dev2_full_duplex_with_speed_former fail, ret = %d\n", ret);
        return ret;
    }

    transfer_cnt = spi_dev2_duplex_comm_get_cnt(write_info, read_info, &total_len);
    if ((transfer_cnt == INVALID_TRANSFER_CNT) || (transfer_cnt == 0)) {
        uart_printf_func("spi_dev2_duplex_comm_get_cnt error, transfer_cnt = %u, total_len = %u\n",
            transfer_cnt, total_len);
        return FP_RET_FAIL;
    }

    transfers = (struct spi_transfer *)malloc_coherent(sizeof(*transfers) * transfer_cnt);
    if (!transfers) {
        uart_printf_func("malloc_coherent fail, transfers is NULL\n");
        return FP_RET_FAIL;
    }
    dma_buffer = (unsigned char *)malloc_coherent(total_len);
    if (!dma_buffer) {
        uart_printf_func("malloc_coherent fail, dma_buffer is NULL\n");
        goto FREE_PART;
    }

    ret = memcpy_s(dma_buffer, total_len, FP_ADDR_CAST(void, write_info->buf_addr), write_info->buf_len);
    if (ret != EOK) {
        uart_printf_func("memcpy_s fail, ret = %d\n", ret);
        goto FREE_ALL;
    }
    spi_dev2_full_duplex_comm_get_joint_data(transfers, dma_buffer, total_len, transfer_cnt);

    mutex_flag = true;
    ret = spi_dev2_full_duplex_comm_transfer_with_speed(transfers, transfer_cnt, speed);
    mutex_flag = false;
    if (ret == -EFAULT) {
        uart_printf_func("spi_dev2_full_duplex_comm_transfer_with_speed fail\n");
        goto FREE_ALL;
    }

    (void)memcpy_s(FP_ADDR_CAST(void, read_info->buf_addr), read_info->buf_len, dma_buffer, read_info->buf_len);
FREE_ALL:
    if (dma_buffer)
        free(dma_buffer);
FREE_PART:
    if (transfers)
        free(transfers);

    return ret;
}

static int spi_dev2_half_duplex_get_xfer_cnt(struct spi_transfer **transfers, struct spi_transaction_info *write_info,
    struct spi_transaction_info *read_info, int *total_len, int *xfer_cnt)
{
    if (read_info != NULL)
        *total_len = read_info->buf_len;
    else if (FP_ADDR_CAST(void, write_info->buf_addr) != NULL)
        *total_len = write_info->buf_len;

    if (*total_len > FP_DMA_SIZE)
        return -EFAULT;

    *xfer_cnt = (*total_len / MAX_TRANSFER_LEN) + 1; // counts of transferings
    if ((*total_len % MAX_TRANSFER_LEN) != 0)
        *xfer_cnt += 1; // for transfering header

    // transfers is judged by driver_spi_dev2_half_duplex_with_speed
    *transfers = (struct spi_transfer *)malloc_coherent(sizeof(**transfers) * (*xfer_cnt));

    return FP_RET_SUCCESS;
}

static int spi_dev2_half_duplex_read_xfer_setup(struct spi_transaction_info *trans_info,
    struct spi_transfer *transfers, int total_len, int xfer_cnt)
{
    int transfer_len;
    int offset = 0;

    // the first transfer has been inited by spi_dev2_half_duplex_xfer_setup
    for (int i = 1; i < xfer_cnt; i++) {
        transfer_len = (total_len <= MAX_TRANSFER_LEN) ? total_len : MAX_TRANSFER_LEN;
        transfers[i].cs_change = 0;
        if (i == (xfer_cnt - 1))
            transfers[i].cs_change = true;
        transfers[i].delay_usecs = 0;
        transfers[i].rx_buf = FP_ADDR_CAST(void, (trans_info->buf_addr + offset));
        transfers[i].tx_buf = NULL;
        transfers[i].len = transfer_len;
        total_len -= transfer_len;
        offset += transfer_len;
    }
    return FP_RET_SUCCESS;
}

static int spi_dev2_half_duplex_write_xfer_setup(struct spi_transaction_info *trans_info,
    struct spi_transfer *transfers, int total_len, int xfer_cnt)
{
    int transfer_len;
    int offset = 0;

    // the first transfer has been inited by spi_dev2_half_duplex_xfer_setup
    for (int i = 1; i < xfer_cnt; i++) {
        transfer_len = (total_len <= MAX_TRANSFER_LEN) ? total_len : MAX_TRANSFER_LEN;
        transfers[i].cs_change = 0;
        if (i == (xfer_cnt - 1))
            transfers[i].cs_change = true;
        transfers[i].delay_usecs = 0;
        transfers[i].tx_buf = FP_ADDR_CAST(void, (trans_info->buf_addr + offset));
        transfers[i].rx_buf = NULL;
        transfers[i].len = transfer_len;
        total_len -= transfer_len;
        offset += transfer_len;
    }
    return FP_RET_SUCCESS;
}

static int spi_dev2_half_duplex_xfer_setup(struct spi_transfer *transfers, struct spi_transaction_info *write_info,
    struct spi_transaction_info *read_info, int total_len, int xfer_cnt)
{
    int ret = FP_RET_SUCCESS;

    transfers[0].cs_change = false;
    transfers[0].delay_usecs = 0;
    transfers[0].tx_buf = FP_ADDR_CAST(void, write_info->reg_addr);
    transfers[0].rx_buf = NULL;
    transfers[0].len = write_info->reg_len;

    if ((read_info == NULL) && (FP_ADDR_CAST(void, write_info->buf_addr) == NULL))
        transfers[0].cs_change = true;

    if (read_info != NULL)
        ret = spi_dev2_half_duplex_read_xfer_setup(read_info, transfers, total_len, xfer_cnt);
    else if (FP_ADDR_CAST(void, write_info->buf_addr) != NULL)
        ret = spi_dev2_half_duplex_write_xfer_setup(write_info, transfers, total_len, xfer_cnt);

    return ret;
}

static int spi_dev2_half_duplex_start(struct spi_transfer *transfers, int xfer_cnt, int speed)
{
    int ret;
    struct spi_message msg = {0};
    struct spi_device spi_set = {
        .max_speed_hz = speed,
        .mode = SPI_MODE_0,
        .bits_per_word = FP_BITS_PER_WORD,
        .controller_data = &chip_dev2_info,
    };

    msg.transfers = transfers;
    msg.transfer_num = xfer_cnt;

    if (transfers == NULL) {
        uart_printf_func("transfers or rx_data is null!\n");
        return -EFAULT;
    }

    ret = hisi_spi_init(spi_base_addr, &spi_set);
    if (ret != FP_RET_SUCCESS)
        return -EFAULT;

    hisi_spi_polling_transfer(spi_base_addr, &msg);
    hisi_spi_exit(spi_base_addr);

    return msg.status;
}

static void spi_dev2_half_duplex_done(struct spi_transfer *transfers)
{
    if (transfers != NULL) {
        free(transfers);
        transfers = NULL;
    }
}

static int driver_spi_dev2_half_duplex_with_speed_former(struct spi_transaction_info *write_info,
    struct spi_transaction_info *read_info, int speed)
{
    struct spi_device spi_set = {
        .max_speed_hz = speed,
        .mode = SPI_MODE_0,
        .bits_per_word = FP_BITS_PER_WORD,
        .controller_data = &chip_dev2_info,
    };

    if (write_info == NULL)
        return -EFAULT;

    return fp_spi_driver(write_info, read_info, &spi_set);
}

int driver_spi_dev2_half_duplex_with_speed(struct spi_transaction_info *write_info,
    struct spi_transaction_info *read_info, int speed)
{
    int ret;
    int xfer_cnt = 0;
    int total_len = 0;
    struct spi_transfer *transfers = NULL;

    if (fp_check_return(g_former_spi_support, ARRAY_SIZE(g_former_spi_support), reg_addr_fp_gpio.product_id)) {
        ret = driver_spi_dev2_half_duplex_with_speed_former(write_info, read_info, speed);
        if (ret != FP_RET_SUCCESS)
            uart_printf_func("driver_spi_dev2_full_duplex_with_speed_former fail, ret = %d\n", ret);
        return ret;
    }

    if (write_info == NULL)
        return -EFAULT;

    ret = spi_dev2_half_duplex_get_xfer_cnt(&transfers, write_info, read_info, &total_len, &xfer_cnt);
    if ((ret != FP_RET_SUCCESS) || (transfers == NULL))
        return -EFAULT;

    ret = spi_dev2_half_duplex_xfer_setup(transfers, write_info, read_info, total_len, xfer_cnt);
    if (ret != FP_RET_SUCCESS)
        goto EXIT;

    mutex_flag = true;
    ret = spi_dev2_half_duplex_start(transfers, xfer_cnt, speed);
    if (ret != FP_RET_SUCCESS)
        uart_printf_func("spi_dev2_half_duplex_start fail, ret = %d\n", ret);
    mutex_flag = false;
EXIT:
    spi_dev2_half_duplex_done(transfers);

    return ret;
}
#endif

int get_fingerprint_gpio_num(int *gpio_num)
{
    int fp_gpio_num;
    char gpio_base[GPIO_BASE_SIZE] = {0};

    if (!gpio_num)
        return FP_RET_FAIL;
    if (get_shared_mem_info(TEEOS_SHARED_MEM_FINGERPRINT, (unsigned int *)gpio_base, sizeof(gpio_base))) {
        uart_printf_func("map fingerprint_gpio_base failed\n");
        return -FPC_GPIO_INIT_ERROR;
    }

    // fp_gpio_num is used in tui config: If fingerprint gpio num is in the same group of TUI gpio num,
    // then we must response to fingerprint irq when TUI is displaying.
    fp_gpio_num = readl((int)(gpio_base + RAM_ADDR_FINGERPRINT_GPIO_IRQ_NUM));
    *gpio_num = fp_gpio_num;
    return FP_RET_SUCCESS;
}

int spi_tui_mutex(void)
{
    return mutex_flag;
}

int fingerprint_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    uint32_t ret;
    uint64_t temp_addr_fp;
    uint64_t write_addr_fp;
    uint64_t read_addr_fp;

    if (params == NULL || params->args == 0) {
        uart_printf_func("error:params is null\n");
        return FP_RET_FAIL;
    }
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
    SYSCALL_PERMISSION(SW_SYSCALL_FP_COMMAND_INFO, permissions, FP_GROUP_PERMISSION)
    temp_addr_fp = args[FP_PARA_FIRST];
    ACCESS_CHECK_A64(temp_addr_fp, sizeof(struct fp_cmd_info));
    ACCESS_WRITE_RIGHT_CHECK(temp_addr_fp, sizeof(struct fp_cmd_info));
    if (FP_ADDR_CAST(void, temp_addr_fp) != NULL) {
        if ((FP_ADDR_CAST(struct fp_cmd_info, temp_addr_fp))->command == FINGERPRINT_GET_SENSORHUB_FALLBACK_IMG ||
            (FP_ADDR_CAST(struct fp_cmd_info, temp_addr_fp))->command == FINGERPRINT_GET_SENSORHUB_CAC_IMG) {
            fp_access_check(fp_cmd_info, sh_img_buf, sh_img_size);
            fp_access_write_right_check(fp_cmd_info, sh_img_buf, sh_img_size);
        }
    }
    ret = (uint32_t)driver_fingerprint_command(FP_ADDR_CAST(struct fp_cmd_info, temp_addr_fp));
    args[FP_PARA_FIRST] = ret;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_FP_SPI_TRANSACTION, permissions, FP_GROUP_PERMISSION)
    fp_spi_check(spi_transaction_info);
    ret = (uint32_t)driver_spi_full_duplex(FP_ADDR_CAST(struct spi_transaction_info, write_addr_fp),
        FP_ADDR_CAST(struct spi_transaction_info, read_addr_fp));
    args[FP_PARA_FIRST] = ret;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_FP_SPI_FULL_DUPLEX_WITH_SPEED_TRANSACTION, permissions, FP_GROUP_PERMISSION)
    fp_spi_check(spi_transaction_info);

    ret = (uint32_t)driver_spi_full_duplex_with_speed(FP_ADDR_CAST(struct spi_transaction_info, write_addr_fp),
        FP_ADDR_CAST(struct spi_transaction_info, read_addr_fp), (int)args[FP_PARA_THIRD]);
    args[FP_PARA_FIRST] = ret;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_FP_SPI_HALF_DUPLEX_WITH_SPEED_TRANSACTION, permissions, FP_GROUP_PERMISSION)
    fp_spi_check(spi_transaction_info);

    ret = (uint32_t)driver_spi_half_duplex_with_speed(FP_ADDR_CAST(struct spi_transaction_info, write_addr_fp),
        FP_ADDR_CAST(struct spi_transaction_info, read_addr_fp), (int)args[FP_PARA_THIRD]);
    args[FP_PARA_FIRST] = ret;
    SYSCALL_END

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
    SYSCALL_PERMISSION(SW_SYSCALL_FP_SPI_DEV2_TRANSACTION, permissions, FP_GROUP_PERMISSION)
    fp_spi_check(spi_transaction_info);

    ret = (uint32_t)driver_spi_dev2_full_duplex(FP_ADDR_CAST(struct spi_transaction_info, write_addr_fp),
        FP_ADDR_CAST(struct spi_transaction_info, read_addr_fp));
    args[FP_PARA_FIRST] = ret;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_FP_SPI_DEV2_FULL_DUPLEX_WITH_SPEED_TRANSACTION, permissions, FP_GROUP_PERMISSION)
    fp_spi_check(spi_transaction_info);

    ret = (uint32_t)driver_spi_dev2_full_duplex_with_speed(FP_ADDR_CAST(struct spi_transaction_info, write_addr_fp),
        FP_ADDR_CAST(struct spi_transaction_info, read_addr_fp), (int)args[FP_PARA_THIRD]);
    args[FP_PARA_FIRST] = ret;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_FP_SPI_DEV2_HALF_DUPLEX_WITH_SPEED_TRANSACTION, permissions, FP_GROUP_PERMISSION)
    fp_spi_check(spi_transaction_info);

    ret = (uint32_t)driver_spi_dev2_half_duplex_with_speed(FP_ADDR_CAST(struct spi_transaction_info, write_addr_fp),
        FP_ADDR_CAST(struct spi_transaction_info, read_addr_fp), (int)args[FP_PARA_THIRD]);
    args[FP_PARA_FIRST] = ret;
    SYSCALL_END

    SYSCALL_PERMISSION(SW_SYSCALL_FP_SET_SPI_MODE, permissions, FP_GROUP_PERMISSION)
    ret = (uint32_t)fp_set_spi_mode((unsigned int)args[FP_PARA_FIRST]);
    args[FP_PARA_FIRST] = ret;
    SYSCALL_END;

#endif
    default:
        return FP_RET_FAIL;
    }
    return 0;
}

DECLARE_TC_DRV(
    fingerprint,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    fingerprint_dma_init,
    NULL,
    fingerprint_syscall,
    NULL,
    NULL
);

