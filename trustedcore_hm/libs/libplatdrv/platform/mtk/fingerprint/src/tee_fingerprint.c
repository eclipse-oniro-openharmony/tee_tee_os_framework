/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: MTK Tee Fingerprint Driver Source File
 * Author: tangjianbo
 * Create: 2020-01-21
 */
#include "tee_fingerprint.h"
#include <stdlib.h>
#include <stdio.h>
#include <drv_module.h>
#include <drv_pal.h>
#include "sre_syscalls_id_ext.h"
#include "sre_access_control.h"
#include "spi.h"
#include "gpio_mtk.h"
#include "boot_sharedmem.h"
#include "securec.h"
#include <hmdrv_stub.h> /* keep this at last */

#define RAM_ADDR_FINGERPRINT_GPIO_RST       0x0
#define RAM_ADDR_FINGERPRINT_GPIO_CS        0x4
#define RAM_ADDR_FINGERPRINT_GPIO_IRQ       0x8
#define RAM_ADDR_FINGERPRINT_GPIO_MODULEID  0xC
#define RAM_ADDR_FINGERPRINT_GPIO_IRQ_NUM   0x10
#define RAM_ADDR_FINGERPRINT_SPI_FREQ       0x14
#define RAM_ADDR_FINGERPRINT_FPC2050        0x18
#define RAM_ADDR_FINGERPRINT_PRODUCT        0x1C

#define FP_IRQ_PIN_PULLTYPE_NONE            0x0
#define FP_IRQ_PIN_PULLTYPE_UP              0x1
#define FP_IRQ_PIN_PULLTYPE_DOWN            0x2

#define FP_RET_SUCCESS                      0
#define FP_RET_FAIL                         (-1)

#define MEM_DATA_SIZE 8
#define FP_CHECK_NUM  0x66BB
#define OFFSET_8      8
#define OFFSET_16     16
#define SPI_SPEED_PARA 109200000

#define OCEAN_PRJ     89
#define YORK_PRJ      96

#define SPI_ALIGN_4_SIZE(X)    ((X) % 4 ? ((X) + 4) - ((X) & (0x3)) : (X))
#define SPI_ALIGN_1024_SIZE(X) (((X) % 1024 && (X) > 1024) ? ((X) + 1024) - ((X) % 1024) : (X))

#define fp_check_ret(ret) do {                                                                   \
    if ((ret) != 0)                                                                              \
        uart_printf_func("%s: %d: memcpy_s failed! ret = %d\n", __func__, __LINE__, (ret));      \
} while (0)

#define pointer_free(ptr) do { \
    if ((ptr) != NULL) {       \
        free(ptr);             \
        (ptr) = NULL;          \
    }                          \
} while (0)

#define FP_ADDR_CAST(type, addr) (struct type *)(uintptr_t)(addr)
/* change the the address of TA to address of driver */
#define fp_spi_read_check(type) do {                             \
    write_addr_fp = args[0];                                    \
    read_addr_fp  = args[1];                                    \
    ACCESS_CHECK_A64(write_addr_fp, sizeof(struct type));            \
    ACCESS_CHECK_A64(read_addr_fp, sizeof(struct type));             \
    ACCESS_READ_RIGHT_CHECK(write_addr_fp, sizeof(struct type)); \
    ACCESS_READ_RIGHT_CHECK(read_addr_fp, sizeof(struct type));  \
} while (0)

#define fp_spi_write_check_rx(type, rx) do {                                                                 \
    if ((void *)(uintptr_t)(rx) != NULL) {                                                                   \
        ACCESS_CHECK_A64(((struct type *)(uintptr_t)(rx))->reg_addr, ((struct type *)(uintptr_t)(rx))->reg_len); \
        ACCESS_WRITE_RIGHT_CHECK(((struct type *)(uintptr_t)(rx))->reg_addr,                                 \
            ((struct type *)(uintptr_t)(rx))->reg_len);                                                      \
        ACCESS_CHECK_A64(((struct type *)(uintptr_t)(rx))->buf_addr, ((struct type *)(uintptr_t)(rx))->buf_len); \
        ACCESS_WRITE_RIGHT_CHECK(((struct type *)(uintptr_t)(rx))->buf_addr,                                 \
            ((struct type *)(uintptr_t)(rx))->buf_len);                                                      \
    }                                                                                                        \
} while (0)

#define fp_spi_check(type) do {                 \
    fp_spi_read_check(type);                    \
    fp_spi_write_check_rx(type, write_addr_fp); \
    fp_spi_write_check_rx(type, read_addr_fp);  \
} while (0)

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6873) || \
    (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6853) || \
    (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6885)
// extern int __smc_switch_to_atf(uint32_t smc_fid, kcall_tee_smc_atf_t *param);
extern int __smc_switch_to_atf(uint32_t smc_fid, void *info);
#endif

static struct mt_chip_conf g_fpc_spi_chip_config;
static struct spi_user_conf g_fpc_spi_user_conf;
static struct fp_dts_conf g_fp_dts_conf;

enum {
    WAKEUP_NOT_CALL = 0,
    WAKEUP_SUCCESS,
    WAKEUP_FAIL
};

static void fpc_spi_config(struct mt_chip_conf *chip_config)
{
    chip_config->setup_time = 10;
    chip_config->hold_time = 10;
    chip_config->high_time = 12;
    chip_config->low_time = 12;
    chip_config->cs_idle_time = 2;
    chip_config->ulthgh_thrsh = 0;

    chip_config->cpol = 0;
    chip_config->cpha = 0;

    chip_config->rx_mlsb = 1;
    chip_config->tx_mlsb = 1;

    chip_config->tx_endian = 0;
    chip_config->rx_endian = 0;

    chip_config->com_mod = 0;
    chip_config->pause = 0;
    chip_config->finish_intr = 1;
    chip_config->deassert = 0;
    chip_config->ulthigh = 0;
    chip_config->tckdly = 0;
}

static int check_fp_num(void)
{
    if ((g_fp_dts_conf.head_check != FP_CHECK_NUM) ||
        (g_fp_dts_conf.tail_check != FP_CHECK_NUM)) {
        tloge("check_fp_num, maybe uninitialized or modified, head_check 0x%x, tail_check 0x%x\n",
            g_fp_dts_conf.head_check, g_fp_dts_conf.tail_check);
        return FP_RET_FAIL;
    }
    return FP_RET_SUCCESS;
}

static int load_fp_config(void)
{
    int ret;
    uint8_t shared_mem[MEM_DATA_SIZE];

    tlogd("enter load_fp_config\n");
    if (check_fp_num() == FP_RET_SUCCESS) {
        tlogi("load_fp_config has been initialized\n");
        return FP_RET_SUCCESS;
    }
    /* clear g_fp_dts_conf zero */
    (void)memset_s((void*)&g_fp_dts_conf, sizeof(g_fp_dts_conf), 0, sizeof(g_fp_dts_conf));

    /* map g_fp_dts_conf ddr memory address */
    ret = (UINT32)get_shared_mem_info(TEEOS_SHARED_MEM_FINGERPRINT,
        (unsigned int *)shared_mem, sizeof(shared_mem));
    if (ret) {
        tloge("Get sharemem info Failed, ret is 0x%x.\n", ret);
        return FP_RET_FAIL;
    }
    g_fp_dts_conf.sensor_type = shared_mem[INDEX_SENSOR_TYPE];
    g_fp_dts_conf.spi_bus = shared_mem[INDEX_SPI_BUS];
    g_fp_dts_conf.head_check = shared_mem[INDEX_HEAD_CHECK_LOW] |
        (shared_mem[INDEX_HEAD_CHECK_HIGH] << OFFSET_8);
    g_fp_dts_conf.product_id = shared_mem[INDEX_PRODUCT_ID_LOW] |
        (shared_mem[INDEX_PRODUCT_ID_HIGH] << OFFSET_8);
    g_fp_dts_conf.tail_check = shared_mem[INDEX_TAIL_CHECK_LOW] |
        (shared_mem[INDEX_TAIL_CHECK_HIGH] << OFFSET_8);

    tlogi("get head_check = 0x%x\n", g_fp_dts_conf.head_check);
    tlogi("get spi_bus = %d\n", g_fp_dts_conf.spi_bus);
    tlogi("get product_id = %d\n", g_fp_dts_conf.product_id);
    tlogi("get sensor_type = %d\n", g_fp_dts_conf.sensor_type);
    tlogi("get tail_check = 0x%x", g_fp_dts_conf.tail_check);

    if (check_fp_num() != FP_RET_SUCCESS) {
        tloge("load_fp_config sharemem is wrong\n");
        return FP_RET_FAIL;
    }
    tlogd("load_fp_config exit\n");
    return FP_RET_SUCCESS;
}

void driver_set_irq_pin_pulltype(unsigned int pulltype)
{
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6873)
    switch (pulltype) {
    case FP_IRQ_PIN_PULLTYPE_NONE:
        set_gpio_15_pull(0, 0);
        break;
    case FP_IRQ_PIN_PULLTYPE_UP:
        set_gpio_15_pull(1, 0);
        break;
    case FP_IRQ_PIN_PULLTYPE_DOWN:
        set_gpio_15_pull(0, 1);
        break;
    default:
        break;
    }
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6853)
    switch (pulltype) {
    case FP_IRQ_PIN_PULLTYPE_NONE:
        set_gpio_44_pull(0, 0);
        break;
    case FP_IRQ_PIN_PULLTYPE_UP:
        set_gpio_44_pull(1, 0);
        break;
    case FP_IRQ_PIN_PULLTYPE_DOWN:
        set_gpio_44_pull(0, 1);
        break;
    default:
        break;
    }
#else
    switch (pulltype) {
    case FP_IRQ_PIN_PULLTYPE_NONE:
        set_gpio_5_pull(0, 0);
        break;
    case FP_IRQ_PIN_PULLTYPE_UP:
        set_gpio_5_pull(1, 0);
        break;
    case FP_IRQ_PIN_PULLTYPE_DOWN:
        set_gpio_5_pull(0, 1);
        break;
    default:
        break;
    }
#endif
}

static u8 get_product_id(void)
{
    return g_fp_dts_conf.product_id;
}

static void fp_spi_init(void)
{
    static int is_spi_init = 0;
    uint64_t spi_dma_phy_addr = get_spi_dma_addr();

    if (is_spi_init == 0 && spi_dma_phy_addr != INVALID_DMA_ADDRESS) {
        spi_init(g_fp_dts_conf.spi_bus, spi_dma_phy_addr, &g_fpc_spi_user_conf);
        is_spi_init = 1; // spi has been initialized, needn't init again
    }
}

int driver_read_data_from_sensorhub(uint8_t *image_buf)
{
    if (image_buf == NULL)
        return FP_RET_FAIL;

    *image_buf = WAKEUP_FAIL;
    return FP_RET_SUCCESS;
}

int driver_fingerprint_command(struct fp_cmd_info *command_info)
{
    if (command_info == NULL) {
        uart_printf_func("command_info is null\n");
        /* the -1 is error in the file */
        return FP_RET_FAIL;
    }

    int error = FP_RET_SUCCESS;

    switch (command_info->command) {
    case FINGERPRINT_SPI_INIT:
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6853) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6885)
        if (load_fp_config() != FP_RET_SUCCESS) {
            tloge("fp dts cofig or spi not initialized\n");
            return FP_RET_FAIL;
        }
#endif

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6853)
        fp_spi_init();
#endif
        fpc_spi_config(&g_fpc_spi_chip_config);
        break;
    case FINGERPRINT_READ_INT_STATUS:
        break;
    case FINGERPRINT_RESET_SENSOR:
    case FINGERPRINT_DEV2_RESET_SENSOR:
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6873)
        set_gpio_14_data_out(command_info->reset_pin_value);
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6853)
        set_gpio_47_data_out(command_info->reset_pin_value);
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6885)
        if (g_fp_dts_conf.product_id == OCEAN_PRJ)
            // base addr:0x10005120, offset:18
            set_gpio_data_out(0x10005120, 18, command_info->reset_pin_value);
        else if (g_fp_dts_conf.product_id == YORK_PRJ)
            // base addr:0x10005100, offset:14
            set_gpio_data_out(0x10005100, 14, command_info->reset_pin_value);
#else
        set_gpio_171_data_out(command_info->reset_pin_value);
#endif
        break;
    case FINGERPRINT_READ_MODULE_STATUS:
        break;
    case FINGERPRINT_GET_PRODUCT_INFO:
        command_info->product_value = get_product_id();
        break;
    case FINGERPRINT_GET_SENSORHUB_CAC_IMG:
        break;
    case FINGERPRINT_GET_SENSORHUB_FALLBACK_IMG:
        error = driver_read_data_from_sensorhub(FP_ADDR_CAST(uint8_t, command_info->sensorhub_img_buf));
        break;
    case FINGERPRINT_SET_RESET_PIN_DIRECTION:
        break;
    case FINGERPRINT_SET_IRQ_PIN_PULLTYPE:
        driver_set_irq_pin_pulltype(command_info->irq_pin_pull_type);
        break;
    case FINGERPRINT_DISABLE_IRQ:
        break;
    default:
        break;
    }
    return error;
}

static int fp_spi_driver_value_init(void **tx_buff, void **rx_buff, uint32_t align_buff_size)
{
    if (align_buff_size <= 0) {
        uart_printf_func("malloc size do not is 0\n");
        return FP_RET_FAIL;
    }

    *tx_buff = malloc(align_buff_size);
    if (*tx_buff == NULL) {
        uart_printf_func("tx_buff malloc failed\n");
        return FP_RET_FAIL;
    }
    (void)memset_s(*tx_buff, align_buff_size, 0, align_buff_size);

    *rx_buff = malloc(align_buff_size);
    if (*rx_buff == NULL) {
        uart_printf_func("rx_buff malloc failed\n");
        return FP_RET_FAIL;
    }
    (void)memset_s(*rx_buff, align_buff_size, 0, align_buff_size);
    return FP_RET_SUCCESS;
}

int set_spi_dma_permisson(enum devapc_master_req_type devapc_master_req,
    enum devapc_protect_on_off devapc_protect, enum spi_protect_index spi)
{
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6873) || \
    (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6853) || \
    (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6885)
    int ret;
    uint64_t smc_ret = 0;
    struct hieps_smc_atf hieps_smc_data = {
        .x1 = devapc_master_req,
        .x2 = devapc_protect,
        .x3 = spi,
        .x4 = (uint64_t)&smc_ret,
    };

    ret = __smc_switch_to_atf(MTK_SIP_TEE_HAL_MASTER_TRANS_AARCH64, &hieps_smc_data);
    if (ret != FP_RET_SUCCESS) {
        tloge("TEEOS to ATF spi dma failed! ret = 0x%x, smc_ret = 0x%x\n", ret, smc_ret);
        return FP_RET_FAIL;
    }
    return FP_RET_SUCCESS;
#else
    return FP_RET_SUCCESS;
#endif
}

static void fp_set_spi_speed(int speed)
{
    if (speed <= 0) {
        uart_printf_func("speed is wrong\n");
        return;
    }

    int div = (int)((float)SPI_SPEED_PARA / speed + 0.5);  // spi frequency division

    div = (div % 2 == 1) ? (div + 1) : div;
    g_fpc_spi_chip_config.high_time = div / 2;
    g_fpc_spi_chip_config.low_time = g_fpc_spi_chip_config.high_time;
}

static int fp_driver_spi(struct spi_transaction_info *write_info, struct spi_transaction_info *read_info)
{
    int ret;
    uint32_t tx_bytes;
    uint32_t rx_bytes = 0;
    void *tx_buff = NULL;
    void *rx_buff = NULL;
    /*
     * we use 4Byte align size to avoid memory occupied when spi copy-to-user
     * and copy-from-user.(spi copy must be 4B align)
     */
    uint32_t align_buff_size;

    tx_bytes = write_info->reg_len + write_info->buf_len;
    rx_bytes = (read_info != NULL) ? (read_info->reg_len + read_info->buf_len) : rx_bytes;

    align_buff_size = SPI_ALIGN_4_SIZE(tx_bytes + rx_bytes);

    ret = fp_spi_driver_value_init(&tx_buff, &rx_buff, align_buff_size); /* init tx and rx */
    if (ret != FP_RET_SUCCESS)
        goto out;

    ret = memcpy_s((uint8_t *)tx_buff, align_buff_size, write_info->reg_addr, write_info->reg_len);
    fp_check_ret(ret);
    if (write_info->buf_addr == NULL)
        ret = memset_s((uint8_t *)tx_buff + write_info->reg_len,
                       align_buff_size - write_info->reg_len, 0, write_info->buf_len);
    else
        ret = memcpy_s((uint8_t *)tx_buff + write_info->reg_len,
                       align_buff_size - write_info->reg_len, write_info->buf_addr, write_info->buf_len);
    fp_check_ret(ret);
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6853)
    set_spi_dma_permisson(DEVAPC_MASTER_REQ_SPI, DEVAPC_PROTECT_ENABLE, g_fp_dts_conf.spi_bus);
#else
    set_spi_dma_permisson(DEVAPC_MASTER_REQ_SPI, DEVAPC_PROTECT_ENABLE, SPI0);
#endif
    g_fpc_spi_user_conf.flag = 1; /* 1:end flag */
    /* Send data */
    ret = spi_send(tx_buff, rx_buff, tx_bytes + rx_bytes, &g_fpc_spi_chip_config, &g_fpc_spi_user_conf);

    if (ret != FP_RET_SUCCESS) {
        uart_printf_func("spi_send failed ret = %d\n", ret);
        ret = FP_RET_FAIL;
        goto out;
    }
    if (read_info != NULL) {
        ret = memcpy_s(read_info->buf_addr, read_info->buf_len, (uint8_t *)rx_buff + tx_bytes, read_info->buf_len);
        fp_check_ret(ret);
    }
out:
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MT6853)
    set_spi_dma_permisson(DEVAPC_MASTER_REQ_SPI, DEVAPC_PROTECT_DISABLE, g_fp_dts_conf.spi_bus);
#else
    set_spi_dma_permisson(DEVAPC_MASTER_REQ_SPI, DEVAPC_PROTECT_DISABLE, SPI0);
#endif
    pointer_free(tx_buff);
    pointer_free(rx_buff);
    return ret;
}

int driver_spi_full_duplex(struct spi_transaction_info *write_info, struct spi_transaction_info *read_info)
{
    if (write_info == NULL) {
        uart_printf_func("write_info is NULL\n");
        return FP_RET_FAIL;
    }
    return fp_driver_spi(write_info, read_info);
}

int driver_spi_full_duplex_with_speed(struct spi_transaction_info *write_info,
                                      struct spi_transaction_info *read_info, int speed)
{
    if (write_info == NULL) {
        uart_printf_func("write_info is NULL\n");
        return FP_RET_FAIL;
    }

    fp_set_spi_speed(speed);

    return fp_driver_spi(write_info, read_info);
}

static int fingerprint_dma_init(void)
{
    (void)memset_s(&g_fpc_spi_chip_config, sizeof(g_fpc_spi_chip_config),
        0, sizeof(g_fpc_spi_chip_config));
    (void)memset_s(&g_fpc_spi_user_conf, sizeof(g_fpc_spi_user_conf),
        0, sizeof(g_fpc_spi_user_conf));
#ifndef MT6853_UNIQUE_FEATURE
    uint64_t spi_dma_phy_addr = get_spi_dma_addr();
    if (spi_dma_phy_addr == INVALID_DMA_ADDRESS) {
        uart_printf_func("get spi_dma_phy_addr failed\n");
        return FP_RET_FAIL;
    }
    spi_init(SPI0, spi_dma_phy_addr, &g_fpc_spi_user_conf);
#endif
    return FP_RET_SUCCESS;
}

int fingerprint_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    UINT32 ret;
    UINT64 write_addr_fp;
    UINT64 read_addr_fp;

    if (params == NULL) {
        uart_printf_func("error:params is null\n");
        return FP_RET_FAIL;
    }

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_FP_COMMAND_INFO, permissions, FP_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(struct fp_cmd_info));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(struct fp_cmd_info));
        if ((void *)(args[0]) != NULL) {
            if (((FP_ADDR_CAST(fp_cmd_info, args[0]))->command == FINGERPRINT_GET_SENSORHUB_FALLBACK_IMG) ||
                ((FP_ADDR_CAST(fp_cmd_info, args[0]))->command == FINGERPRINT_GET_SENSORHUB_CAC_IMG)) {
                ACCESS_CHECK_A64(((FP_ADDR_CAST(fp_cmd_info, args[0]))->sensorhub_img_buf),
                    (FP_ADDR_CAST(fp_cmd_info, args[0]))->sensorhub_img_size);
                ACCESS_WRITE_RIGHT_CHECK(((FP_ADDR_CAST(fp_cmd_info, args[0]))->sensorhub_img_buf),
                    (FP_ADDR_CAST(fp_cmd_info, args[0]))->sensorhub_img_size);
            }
        }
        ret = (UINT32)driver_fingerprint_command(FP_ADDR_CAST(fp_cmd_info, args[0]));
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_FP_SPI_TRANSACTION, permissions, FP_GROUP_PERMISSION)
        fp_spi_check(spi_transaction_info);
        ret = (UINT32)driver_spi_full_duplex(
            FP_ADDR_CAST(spi_transaction_info, write_addr_fp), FP_ADDR_CAST(spi_transaction_info, read_addr_fp));
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_FP_SPI_FULL_DUPLEX_WITH_SPEED_TRANSACTION, permissions, FP_GROUP_PERMISSION)
        fp_spi_check(spi_transaction_info);
        ret = (UINT32)driver_spi_full_duplex_with_speed(FP_ADDR_CAST(spi_transaction_info, write_addr_fp),
            FP_ADDR_CAST(spi_transaction_info, read_addr_fp), (int)args[2]);
        args[0] = ret;
        SYSCALL_END

        default:
            return FP_RET_FAIL;
    }
    return FP_RET_SUCCESS;
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
