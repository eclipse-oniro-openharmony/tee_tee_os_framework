/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: MTK SPI driver Source File
 * Author: tangjianbo
 * Create: 2020-01-21
 */

#include <drv_mem.h>
#include "spi_reg.h"
#include "spi.h"
#include "sre_log.h"
#include "drv_module.h"
#include <sre_syscall.h>
#include <boot_sharedmem.h>
#include "mem_page_ops.h"
#include "mem_ops.h"

#define SPI_TRANSFER_POLLING

#define SPI_ERR(fmt, args...)  tloge("[spi]"fmt, ##args)
#ifdef SPI_DEBUG
#define SPI_DBG(fmt, args...)  tloge("[spi]"fmt, ##args)
#else
#define SPI_DBG(fmt, args...)
#endif

/* set SPI_PAD=1, if it is just 'SPIx_MISO',  set SPI_PAD=0 */
#define SPI_PAD                  0
#define DMA_TO_DEVICE            1
#define DMA_FROM_DEVICE          2
#define DMA_ALIGN_SIZE           0x40
#define SPI_SPEED_PARA           109200000
#define SPI_MOD_BASE             4
#define SPI_REG_DATA_READ_CNT    20
#define SPI_4B_ALIGN             0x4
#define SPI_128K                 (128 * 1024)
#define SPI_STATUS_TIMEOUT_VALUE 2000
#define SPI_TRANSFER_LIMIT_TIME  500
#define SPI_1K                   1024
#define SPI_TX_DMA_VA_INIT       0x5A
#define SPI_RX_DMA_VA_INIT       0xA5

#define SPI_RET_SUCCESS          0
#define SPI_RET_FAIL             (-1)

#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & (~((align) - 1)))

extern void v7_dma_map_area(const void *, unsigned long, int);   /* lint !e752 */
extern void v7_dma_unmap_area(const void *, unsigned long, int); /* lint !e752 */
extern void *malloc_coherent(size_t n);

/* default chip config */
static const struct mt_chip_conf g_mt_chip_conf_def = {
    .setup_time = 10,
    .hold_time = 10,
    .high_time = 20,
    .low_time = 20,
    .cs_idle_time = 20,
    .ulthgh_thrsh = 0,
    .cpol = 0,
    .cpha = 1,
    .rx_mlsb = 1,
    .tx_mlsb = 1,
    .tx_endian = 0,
    .rx_endian = 0,
    .com_mod = DMA_TRANSFER,
    .pause = 1,
    .finish_intr = 1,
    .deassert = 0,
    .ulthigh = 0,
    .tckdly = 0
};

static const uint8_t g_reg_offset[REG_MAX] = {
    0x00, 0x04, 0x08, 0x0C, 0x10,
    0x14, 0x18, 0x1C, 0x20, 0x24,
    0x28, 0x2C, 0x30
};

static const uint32_t g_spi_addr[SPI_NUM] = {
    SPI0_BASE_ADDR, SPI1_BASE_ADDR, SPI2_BASE_ADDR, SPI3_BASE_ADDR,
    SPI4_BASE_ADDR, SPI5_BASE_ADDR, SPI6_BASE_ADDR, SPI7_BASE_ADDR,
    0,
};

static const uint8_t g_pdn_offset[PDN_MAX] = { 0x88, 0x8c, 0x94 };

static inline uint32_t get_spi_reg_addr(enum spi_reg_index reg_index,
    enum spi_protect_index spi_id)
{
    return g_spi_addr[spi_id] + g_reg_offset[reg_index];
}

static inline uint32_t get_spi_pdn_addr(enum spi_pdn_index pdn_index, struct spi_user_conf *spi_conf)
{
    return spi_conf->spi_pdn_base_va + g_pdn_offset[pdn_index];
}

void set_chip_config(struct mt_chip_conf *ptr, struct spi_user_conf *spi_conf)
{
    if (spi_conf == NULL) {
        SPI_ERR("spi_conf is NULL");
        return;
    }
    struct mt_chip_conf *chip_conf = spi_conf->chip_config;

    if (ptr != NULL) {
        chip_conf->setup_time = ptr->setup_time;
        chip_conf->hold_time = ptr->hold_time;
        chip_conf->high_time = ptr->high_time;
        chip_conf->low_time = ptr->low_time;
        chip_conf->cs_idle_time = ptr->cs_idle_time;
        chip_conf->ulthgh_thrsh = ptr->ulthgh_thrsh;

        chip_conf->cpol = ptr->cpol;
        chip_conf->cpha = ptr->cpha;

        chip_conf->rx_mlsb = ptr->rx_mlsb;
        chip_conf->tx_mlsb = ptr->tx_mlsb;

        chip_conf->tx_endian = ptr->tx_endian;
        chip_conf->rx_endian = ptr->rx_endian;

        chip_conf->com_mod = ptr->com_mod;
        chip_conf->pause = ptr->pause;
        chip_conf->finish_intr = ptr->finish_intr;
        chip_conf->deassert = ptr->deassert;
        chip_conf->ulthigh = ptr->ulthigh;
        chip_conf->tckdly = ptr->tckdly;
    }
}

static void set_spi_transfer(struct spi_transfer *ptr, struct spi_user_conf *spi_conf)
{
    spi_conf->xfer = ptr;
}

static int get_irq_flag(struct spi_user_conf *spi_conf)
{
    return spi_conf->irq_flag;
}

static void set_irq_flag(enum spi_irq_flag flag, struct spi_user_conf *spi_conf)
{
    spi_conf->irq_flag = flag;
}

static int get_pause_status(struct spi_user_conf *spi_conf)
{
    return spi_conf->spi_running;
}

static void set_pause_status(int status, struct spi_user_conf *spi_conf)
{
    spi_conf->spi_running = status;
}

void dump_chip_config(struct mt_chip_conf *chip_config)
{
#ifdef SPI_DEBUG
    if (chip_config != NULL) {
        SPI_DBG("setup_time=%u\n", chip_config->setup_time);
        SPI_DBG("hold_time=%u\n", chip_config->hold_time);
        SPI_DBG("high_time=%u\n", chip_config->high_time);
        SPI_DBG("low_time=%u\n", chip_config->low_time);
        SPI_DBG("cs_idle_time=%u\n", chip_config->cs_idle_time);
        SPI_DBG("ulthgh_thrsh=%u\n", chip_config->ulthgh_thrsh);
        SPI_DBG("cpol=%d\n", chip_config->cpol);
        SPI_DBG("cpha=%d\n", chip_config->cpha);
        SPI_DBG("tx_mlsb=%d\n", chip_config->tx_mlsb);
        SPI_DBG("rx_mlsb=%d\n", chip_config->rx_mlsb);
        SPI_DBG("tx_endian=%d\n", chip_config->tx_endian);
        SPI_DBG("rx_endian=%d\n", chip_config->rx_endian);
        SPI_DBG("com_mod=%d\n", chip_config->com_mod);
        SPI_DBG("pause=%d\n", chip_config->pause);
        SPI_DBG("finish_intr=%d\n", chip_config->finish_intr);
        SPI_DBG("deassert=%d\n", chip_config->deassert);
        SPI_DBG("ulthigh=%d\n", chip_config->ulthigh);
        SPI_DBG("tckdly=%d\n", chip_config->tckdly);
    } else {
        SPI_DBG("dump chip_config is NULL\n");
    }
#else
   (void)chip_config;
#endif
}

static void dump_reg(struct spi_user_conf *spi_conf)
{
#ifdef SPI_DEBUG
    int value;
    enum spi_protect_index spi_id = spi_conf->spi_id;

    SPI_DBG("dump reg SPI%d\n", spi_id);
    SPI_READ(get_spi_reg_addr(REG_CFG0, spi_id), value);
    SPI_DBG("SPI_REG_CFG0=0x%x\n", value);

    SPI_READ(get_spi_reg_addr(REG_CFG1, spi_id), value);
    SPI_DBG("SPI_REG_CFG1=0x%x\n", value);

    SPI_READ(get_spi_reg_addr(REG_TX_SRC, spi_id), value);
    SPI_DBG("SPI_REG_TX_SRC=0x%x\n", value);

    SPI_READ(get_spi_reg_addr(REG_RX_DST, spi_id), value);
    SPI_DBG("SPI_REG_RX_DST=0x%x\n", value);

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_id), value);
    SPI_DBG("SPI_REG_CMD=0x%x\n", value);

    SPI_READ(get_spi_reg_addr(REG_STATUS1, spi_id), value);
    SPI_DBG("SPI_REG_STATUS1=0x%x\n", value);

    SPI_READ(get_spi_reg_addr(REG_CFG2, spi_id), value);
    SPI_DBG("SPI_REG_CFG2=0x%x\n", value);
#else
   (void)spi_conf;
#endif
}

int get_spi_speed(struct spi_user_conf *spi_conf)
{
    int speed;
    struct mt_chip_conf *chip_config = NULL;

    if (spi_conf == NULL) {
        SPI_ERR("spi_conf is NULL");
        return SPI_RET_FAIL;
    }

    chip_config = spi_conf->chip_config;

    speed = SPI_SPEED_PARA / ((chip_config->high_time + 1) + (chip_config->low_time + 1));

    return speed;
}

#ifdef SPI_TEST
static void spi_enable_clk(struct spi_user_conf *spi_conf)
{
    int value;
    int pdn_sta;

    SPI_READ(get_spi_pdn_addr(PDN_CLR, spi_conf), value);

    SPI_READ(get_spi_pdn_addr(PDN_STA, spi_conf), pdn_sta);
    SPI_DBG("before enable spi clk: PDN sta = 0x%x\n", pdn_sta);

    SPI_WRITE(get_spi_pdn_addr(PDN_CLR, spi_conf), value | SPI0_PDN_MASK);

    SPI_READ(get_spi_pdn_addr(PDN_STA, spi_conf), pdn_sta);
    SPI_DBG("after enable spi clk: PDN sta = %x\n", pdn_sta);
}

static void spi_disable_clk(struct spi_user_conf *spi_conf)
{
    int value;
    int pdn_sta;

    SPI_READ(get_spi_pdn_addr(PDN_SET, spi_conf), value);

    SPI_READ(get_spi_pdn_addr(PDN_STA, spi_conf), pdn_sta);
    SPI_DBG("before dis spi clk: PDN sta = %x\n", pdn_sta);

    SPI_WRITE(get_spi_pdn_addr(PDN_SET, spi_conf), value | SPI0_PDN_MASK);

    SPI_READ(get_spi_pdn_addr(PDN_STA, spi_conf), pdn_sta);
    SPI_DBG("after dis spi clk: PDN sta = %x\n", pdn_sta);
}
#endif

void enable_spi5_clk(void)
{
    uint32_t value_clr = 0;
    uint32_t value_set = 0;
    uint32_t value_sta = 0;

    SPI_DBG("enable_spi5_clk");
    SPI_READ(MODULE_SW_CG_2_CLR, value_clr);
    SPI_READ(MODULE_SW_CG_2_SET, value_set);
    SPI_READ(MODULE_SW_CG_2_STA, value_sta);
    SPI_DBG("before enable clk, MODULE_SW_CG_2_CLR:0x%x MODULE_SW_CG_2_SET:0x%x MODULE_SW_CG_2_STA:0x%x",
        value_clr, value_set, value_sta);
    SPI_WRITE(MODULE_SW_CG_2_CLR, CLK_CTL_CFG);
    SPI_READ(MODULE_SW_CG_2_CLR, value_clr);
    SPI_READ(MODULE_SW_CG_2_SET, value_set);
    SPI_READ(MODULE_SW_CG_2_STA, value_sta);
    SPI_DBG("after enable clk, MODULE_SW_CG_2_CLR:0x%x MODULE_SW_CG_2_SET:0x%x MODULE_SW_CG_2_STA:0x%x",
        value_clr, value_set, value_sta);
}

void disable_spi5_clk(void)
{
    uint32_t value_clr = 0;
    uint32_t value_set = 0;
    uint32_t value_sta = 0;

    SPI_DBG("disable_spi5_clk");
    SPI_READ(MODULE_SW_CG_2_CLR, value_clr);
    SPI_READ(MODULE_SW_CG_2_SET, value_set);
    SPI_READ(MODULE_SW_CG_2_STA, value_sta);
    SPI_DBG("before disable clk, MODULE_SW_CG_2_CLR:0x%x MODULE_SW_CG_2_SET:0x%x MODULE_SW_CG_2_STA:0x%x",
        value_clr, value_set, value_sta);
    SPI_WRITE(MODULE_SW_CG_2_SET, CLK_CTL_CFG);
    SPI_READ(MODULE_SW_CG_2_CLR, value_clr);
    SPI_READ(MODULE_SW_CG_2_SET, value_set);
    SPI_READ(MODULE_SW_CG_2_STA, value_sta);
    SPI_DBG("after disable clk, MODULE_SW_CG_2_CLR:0x%x MODULE_SW_CG_2_SET:0x%x MODULE_SW_CG_2_STA:0x%x",
        value_clr, value_set, value_sta);
}

static unsigned int is_interrupt_enable(struct spi_user_conf *spi_conf)
{
    unsigned int cmd = 0;

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), cmd);
    return (cmd >> SPI_CMD_FINISH_IE_OFFSET) & 1;
}

static void clear_pause_bit(struct spi_user_conf *spi_conf)
{
    unsigned int reg_val = 0;

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
    reg_val &= (~SPI_CMD_PAUSE_EN_MASK);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
}

static void set_pause_bit(struct spi_user_conf *spi_conf)
{
    unsigned int reg_val = 0;

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
    reg_val |= (1 << SPI_CMD_PAUSE_EN_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
}

static void clear_resume_bit(struct spi_user_conf *spi_conf)
{
    unsigned int reg_val = 0;

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
    reg_val &= (~SPI_CMD_RESUME_MASK);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
}

void set_spi5_cs(unsigned int value)
{
    unsigned int reg_val = 0;

    SPI_READ((SPI5_BASE_ADDR + REG_CMD), reg_val);
    SPI_DBG("set_spi5_cs reg_val:%x", reg_val);
    if (value == 0)
        reg_val = (reg_val & (~(1 << SPI_CMD_CS_POL_OFFSET)));
    else
        reg_val = (reg_val & (~(1 << SPI_CMD_CS_POL_OFFSET))) | (1 << SPI_CMD_CS_POL_OFFSET);

    SPI_WRITE((SPI5_BASE_ADDR + REG_CMD), reg_val);
    SPI_DBG("now set_spi5_cs reg_val:%x", reg_val);
}

void set_cs_bit(struct spi_user_conf *spi_conf, unsigned int value)
{
    unsigned int reg_val = 0;
    if (spi_conf == NULL) {
        SPI_ERR("spi_conf is NULL");
        return;
    }
    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
    SPI_DBG("spi%d reg_val:%x", spi_conf->spi_id, reg_val);
    if (value == 0)
        reg_val = (reg_val & (~(1 << SPI_CMD_CS_POL_OFFSET)));
    else
        reg_val = (reg_val & (~(1 << SPI_CMD_CS_POL_OFFSET))) | (1 << SPI_CMD_CS_POL_OFFSET);

    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
    SPI_DBG("spi%d reg_val:%x", spi_conf->spi_id, reg_val);
}

static void spi_setup_packet(struct spi_transfer *ptr, struct spi_user_conf *spi_conf)
{
    unsigned int packet_size;
    unsigned int packet_loop;
    unsigned int cfg1 = 0;

    /* set transfer packet and loop */
    if (ptr->len < PACKET_SIZE)
        packet_size = ptr->len;
    else
        packet_size = PACKET_SIZE;

    if (ptr->len % packet_size)
        SPI_ERR("The lens are not a multiple of %d, your len %u", PACKET_SIZE, ptr->len);

    packet_loop = (ptr->len) / packet_size;

    SPI_READ(get_spi_reg_addr(REG_CFG1, spi_conf->spi_id), cfg1);
    cfg1 &= (~(SPI_CFG1_PACKET_LENGTH_MASK + SPI_CFG1_PACKET_LOOP_MASK));
    cfg1 |= ((packet_size - 1) << SPI_CFG1_PACKET_LENGTH_OFFSET);
    cfg1 |= ((packet_loop - 1) << SPI_CFG1_PACKET_LOOP_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CFG1, spi_conf->spi_id), cfg1);
}

static void spi_disable_dma(struct spi_user_conf *spi_conf)
{
    unsigned int cmd = 0;

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), cmd);
    cmd &= (~SPI_CMD_TX_DMA_MASK);
    cmd &= (~SPI_CMD_RX_DMA_MASK);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), cmd);
}

static void spi_enable_dma(struct spi_transfer *xfer, unsigned int mode, struct spi_user_conf *spi_conf)
{
    (void)mode;
    unsigned int cmd = 0;

    (void)memset_s(spi_conf->spi_tx_dma_va, SPI_128K, SPI_TX_DMA_VA_INIT, SPI_128K);
    (void)memset_s(spi_conf->spi_rx_dma_va, SPI_128K, SPI_RX_DMA_VA_INIT, SPI_128K);

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), cmd);
    xfer->tx_dma = spi_conf->spi_tx_dma_ph_addr;
    if ((xfer->tx_buf != NULL) || ((xfer->tx_dma != INVALID_DMA_ADDRESS) && (xfer->tx_dma != 0))) {
        if (xfer->tx_dma & (SPI_4B_ALIGN - 1))
            SPI_ERR("Warning!Tx_DMA address should be 4Byte alignment,buf:%p, dma:%x\n", xfer->tx_buf, xfer->tx_dma);

        SPI_WRITE(get_spi_reg_addr(REG_TX_SRC, spi_conf->spi_id), xfer->tx_dma);
        cmd |= (1 << SPI_CMD_TX_DMA_OFFSET);
    }

    xfer->rx_dma = spi_conf->spi_rx_dma_ph_addr;
    if ((xfer->rx_buf != NULL) || ((xfer->rx_dma != INVALID_DMA_ADDRESS) && (xfer->rx_dma != 0))) {
        if (xfer->rx_dma & (SPI_4B_ALIGN - 1))
            SPI_ERR("Warning!Rx_DMA address should be 4Byte alignment,buf:%p,dma:%x\n", xfer->rx_buf, xfer->rx_dma);

        SPI_WRITE(get_spi_reg_addr(REG_RX_DST, spi_conf->spi_id), (xfer->rx_dma));
        cmd |= (1 << SPI_CMD_RX_DMA_OFFSET);
    }

    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), cmd);
}

static void spi_start_transfer(struct spi_user_conf *spi_conf)
{
    unsigned int reg_val = 0;

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
    reg_val |= (1 << SPI_CMD_ACT_OFFSET);

    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
}

static void spi_resume_transfer(struct spi_user_conf *spi_conf)
{
    unsigned int reg_val = 0;

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
    reg_val &= (~SPI_CMD_RESUME_MASK);
    reg_val |= (1 << SPI_CMD_RESUME_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
}

static void reset_spi(struct spi_user_conf *spi_conf)
{
    unsigned int reg_val = 0;

    /* set the software reset bit in SPI_REG_CMD */
    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
    reg_val &= (~SPI_CMD_RST_MASK);
    reg_val |= (1 << SPI_CMD_RST_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
    reg_val &= (~SPI_CMD_RST_MASK);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_conf->spi_id), reg_val);
}

static unsigned int spi_setup_common(struct mt_chip_conf *chip_config, struct spi_user_conf *spi_conf)
{
    unsigned int reg_val = 0;
    enum spi_protect_index spi_id;

    spi_id = spi_conf->spi_id;
    SPI_READ(get_spi_reg_addr(REG_CFG0, spi_id), reg_val);
    reg_val &= (~(SPI_CFG0_CS_HOLD_MASK | SPI_CFG0_CS_SETUP_MASK));
    reg_val |= ((chip_config->hold_time - 1) << SPI_CFG0_CS_HOLD_OFFSET);
    reg_val |= ((chip_config->setup_time - 1) << SPI_CFG0_CS_SETUP_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CFG0, spi_id), reg_val);

    SPI_READ(get_spi_reg_addr(REG_CFG1, spi_id), reg_val);
    reg_val &= (~(SPI_CFG1_CS_IDLE_MASK));
    reg_val |= ((chip_config->cs_idle_time - 1) << SPI_CFG1_CS_IDLE_OFFSET);
    reg_val &= (~(SPI_CFG1_GET_TICK_DLY_MASK));
    reg_val |= ((chip_config->tckdly) << SPI_CFG1_GET_TICK_DLY_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CFG1, spi_id), reg_val);

    SPI_READ(get_spi_reg_addr(REG_CFG1, spi_id), reg_val);
    reg_val &= (~(SPI_CFG1_REG_VAL_MASK << SPI_CFG1_REG_VAL_OFFSET));
    SPI_WRITE(get_spi_reg_addr(REG_CFG1, spi_id), reg_val);

    SPI_READ(get_spi_reg_addr(REG_CFG2, spi_id), reg_val);
    reg_val &= (~(SPI_CFG0_SCK_HIGH_MASK | SPI_CFG0_SCK_LOW_MASK));
    reg_val |= ((chip_config->high_time - 1) << SPI_CFG0_SCK_HIGH_OFFSET);
    reg_val |= ((chip_config->low_time - 1) << SPI_CFG0_SCK_LOW_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CFG2, spi_id), reg_val);

    SPI_READ(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
    reg_val &= (~(SPI_CMD_TX_ENDIAN_MASK | SPI_CMD_RX_ENDIAN_MASK));
    reg_val &= (~(SPI_CMD_TXMSBF_MASK | SPI_CMD_RXMSBF_MASK));
    reg_val &= (~(SPI_CMD_CPHA_MASK | SPI_CMD_CPOL_MASK));
    reg_val |= (chip_config->tx_mlsb << SPI_CMD_TXMSBF_OFFSET);
    reg_val |= (chip_config->rx_mlsb << SPI_CMD_RXMSBF_OFFSET);
    reg_val |= (chip_config->tx_endian << SPI_CMD_TX_ENDIAN_OFFSET);
    reg_val |= (chip_config->rx_endian << SPI_CMD_RX_ENDIAN_OFFSET);
    reg_val |= (chip_config->cpha << SPI_CMD_CPHA_OFFSET);
    reg_val |= (chip_config->cpol << SPI_CMD_CPOL_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_id), reg_val);

    return reg_val;
}

static void spi_setup(struct mt_chip_conf *chip_config, struct spi_user_conf *spi_conf)
{
    unsigned int reg_val;
    enum spi_protect_index spi_id;

    if (chip_config == NULL) {
        SPI_ERR("%s chip_config is NULL", __func__);
        set_irq_flag(IRQ_IDLE, spi_conf);
        return;
    }
    spi_id = spi_conf->spi_id;
    reg_val = spi_setup_common(chip_config, spi_conf);

#ifdef SPI_TRANSFER_POLLING
    /* disable pause IE in polling mode */
    SPI_READ(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
    reg_val &= (~SPI_CMD_PAUSE_EN_MASK);
    reg_val &= (~SPI_CMD_PAUSE_IE_MASK);
    reg_val |= (chip_config->pause << SPI_CMD_PAUSE_EN_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
#else
    SPI_READ(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
    reg_val &= (~SPI_CMD_PAUSE_EN_MASK);
    reg_val &= (~SPI_CMD_PAUSE_IE_MASK);
    reg_val |= (chip_config->pause << SPI_CMD_PAUSE_EN_OFFSET);
    reg_val |= (chip_config->pause << SPI_CMD_PAUSE_IE_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
#endif
#ifdef SPI_TRANSFER_POLLING
    /* disable finish IE in polling mode */
    SPI_READ(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
    reg_val &= (~SPI_CMD_FINISH_IE_MASK);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
#else
    SPI_READ(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
    reg_val &= (~SPI_CMD_FINISH_IE_MASK);
    reg_val |= (1 << SPI_CMD_FINISH_IE_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
#endif
    /* set the communication of mode */
    SPI_READ(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
    reg_val &= (~SPI_CMD_TX_DMA_MASK);
    reg_val &= (~SPI_CMD_RX_DMA_MASK);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_id), reg_val);

    /* set deassert mode */
    SPI_READ(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
    reg_val &= (~SPI_CMD_DEASSERT_MASK);
    reg_val |= (chip_config->deassert << SPI_CMD_DEASSERT_OFFSET);
    SPI_WRITE(get_spi_reg_addr(REG_CMD, spi_id), reg_val);
    SPI_WRITE(get_spi_reg_addr(REG_PAD_SEL, spi_id), SPI_PAD);
}

static void spi_handle_irq(struct spi_user_conf *spi_conf)
{
    struct spi_transfer *xfer = NULL;
    struct mt_chip_conf *chip_config = NULL;

    unsigned int reg_val;
    unsigned int cnt;
    unsigned int i;

    xfer = spi_conf->xfer;
    chip_config = spi_conf->chip_config;
    if (chip_config == NULL) {
        SPI_ERR("chip_config is NULL\n");
        return;
    }

    /* pause mode */
    if (chip_config->pause) {
        if (get_pause_status(spi_conf) == INPROGRESS)
            set_pause_status(PAUSED, spi_conf);
        else
            SPI_ERR("Wrong spi status\n");
    } else {
        set_pause_status(IDLE, spi_conf);
    }

    if ((chip_config->com_mod == FIFO_TRANSFER) && xfer->rx_buf) {
        cnt = (xfer->len % SPI_MOD_BASE) ? ((xfer->len / SPI_MOD_BASE) + 1) : (xfer->len / SPI_MOD_BASE);
        for (i = 0; i < cnt; i++) {
            SPI_READ(get_spi_reg_addr(REG_RX_DATA, spi_conf->spi_id), reg_val);
            *((unsigned int *)xfer->rx_buf + i) = reg_val;
            if (i < SPI_REG_DATA_READ_CNT)
                SPI_DBG("RX_DATA_REG[%d]:0x%x\n", i, reg_val);
        }
    } else if ((chip_config->com_mod == DMA_TRANSFER) && xfer->rx_buf) {
        cnt = (xfer->len % SPI_MOD_BASE) ? ((xfer->len / SPI_MOD_BASE) + 1) : (xfer->len / SPI_MOD_BASE);
        /* notice to cache flush */
        for (i = 0; i < cnt; i++) {
            SPI_READ((spi_conf->spi_rx_dma_va + (i * SPI_MOD_BASE)), reg_val);
            *((unsigned int *)xfer->rx_buf + i) = reg_val;
            /* print the 10 * 32 bits data */
            if ((i < 10) || (i > (cnt - 10)))
                SPI_DBG("RX_DATA_DMA[%d]:0x%x", i, reg_val);
        }
        SPI_READ(get_spi_reg_addr(REG_TX_SRC, spi_conf->spi_id), reg_val);
        SPI_DBG("SPI_REG_TX_SRC=0x%x\n", reg_val);
        SPI_READ(get_spi_reg_addr(REG_RX_DST, spi_conf->spi_id), reg_val);
        SPI_DBG("SPI_REG_RX_DST=0x%x\n", reg_val);
        SPI_DBG("add to debug the expand tx DMA");
    }

    if ((spi_conf->is_last_xfer == 1) && (xfer->is_transfer_end == 1)) {
        set_pause_status(IDLE, spi_conf);
        reset_spi(spi_conf);
    }
    set_irq_flag(IRQ_IDLE, spi_conf);
}

static void spi_irq_handler(struct spi_user_conf *spi_conf)
{
#ifdef SPI_TRANSFER_POLLING
    unsigned int irq_status;
    /* the default do while times, the 1000000 about 200ms */
    unsigned int irq_status_counter = 1000000;

    do {
        irq_status_counter--;
        if (irq_status_counter == 0) {
            SPI_ERR("%s timeout, SPI%d\n", __func__, spi_conf->spi_id);
            break;
        }
        /* if the spi status1 is low > 2s,the spi transfer will timeout */
        if (irq_status_counter <= SPI_STATUS_TIMEOUT_VALUE)
            SRE_SwMsleep(1);

        SPI_READ(get_spi_reg_addr(REG_STATUS1, spi_conf->spi_id), irq_status);
    } while (irq_status == 0);
#else
    unsigned int ret_val;

    SPI_READ(get_spi_reg_addr(REG_STATUS0, spi_conf->spi_id), ret_val);
    if ((ret_val & 0x00000003) == 0) { /* get last 2 bits */
        SPI_ERR("error spi interrupt status, SPI_REG_STATUS0 %x", ret_val);
        return;
    }
#endif
    spi_handle_irq(spi_conf);
}

static int spi_pasue_status_judge_and_process(struct mt_chip_conf *chip_config, struct spi_user_conf *spi_conf)
{
    int ret = SPI_RET_SUCCESS;

    if (get_pause_status(spi_conf) == PAUSED) {
        set_pause_status(INPROGRESS, spi_conf);
        spi_resume_transfer(spi_conf);
    } else if (get_pause_status(spi_conf) == IDLE) {
        if ((chip_config->pause))
            set_pause_bit(spi_conf);
        set_pause_status(INPROGRESS, spi_conf);
        spi_start_transfer(spi_conf);
    } else {
        ret = SPI_RET_FAIL;
    }
    return ret;
}

static int spi_mode_judge_and_process(struct spi_transfer *xfer, struct mt_chip_conf *chip_config,
    struct spi_user_conf *spi_conf)
{
    unsigned int cnt;
    unsigned int i;
    unsigned int mode;
    int ret = SPI_RET_SUCCESS;

    mode = chip_config->com_mod;
    if ((mode == FIFO_TRANSFER))
        if (xfer->len > FIFO_MAX_LEN) {
            SPI_ERR("xfer len is invalid over fifo size");
            return SPI_RET_FAIL;
        }

    SPI_DBG("len:%u tx_buf:%p rx_buf:%p, mode %u", xfer->len, xfer->tx_buf, xfer->rx_buf, mode);
    /*
     * cannot 1K align & FIFO->DMA need used pause mode
     * this is to clear pause bit (CS turn to idle after data transfer done)
     */
    if (mode == DMA_TRANSFER) {
        if ((spi_conf->is_last_xfer == 1) && (xfer->is_transfer_end == 1))
            clear_pause_bit(spi_conf);
    } else if (mode == FIFO_TRANSFER) {
        if (xfer->is_transfer_end == 1)
            clear_pause_bit(spi_conf);
    } else {
        SPI_ERR("xfer mode is invalid");
        return ret;
    }

    spi_disable_dma(spi_conf);
    spi_setup_packet(xfer, spi_conf);

    if (mode == FIFO_TRANSFER) {
        dump_reg(spi_conf);
        cnt = ((xfer->len) % SPI_MOD_BASE) ? ((xfer->len) / SPI_MOD_BASE + 1) : ((xfer->len) / SPI_MOD_BASE);
        for (i = 0; i < cnt; i++) {
            SPI_WRITE(get_spi_reg_addr(REG_TX_DATA, spi_conf->spi_id), *((unsigned int *)xfer->tx_buf + i));
            SPI_DBG("tx_buf data[%d] is:%x", i, *((unsigned int *)xfer->tx_buf + i));
        }
    }

    if (mode == DMA_TRANSFER) {
        spi_enable_dma(xfer, mode, spi_conf);
        dump_reg(spi_conf);
        SPI_DBG("xfer tx_dma:%08x rx_dma:%08x", xfer->tx_dma, xfer->rx_dma);

        /* if cache is enable for your os, remember to flush cache for SPI DMA memory */
        /* SPI_TX_DMA_VA_BASE and SPI_RX_DMA_VA_BASE */
        cnt = (xfer->len % SPI_MOD_BASE) ? ((xfer->len / SPI_MOD_BASE) + 1) : (xfer->len / SPI_MOD_BASE);
        for (i = 0; i < cnt ; i++) {
            *((unsigned int *) spi_conf->spi_tx_dma_va + i) = *((unsigned int *)xfer->tx_buf + i);
            if (i < SPI_REG_DATA_READ_CNT)
                SPI_DBG("tx_dma data[%d] is:%x", i, *((unsigned int *)xfer->tx_buf + i));
        }
    }
    return ret;
}

static int spi_next_xfer(struct spi_transfer *xfer, struct spi_user_conf *spi_conf)
{
    unsigned int speed;
    int ret;

    struct mt_chip_conf *chip_config = spi_conf->chip_config;
    if (chip_config == NULL) {
        SPI_ERR("%S get chip_config is NULL", __func__);
        ret = SPI_RET_FAIL;
        goto fail;
    }

#ifndef SPI_TRANSFER_POLLING
    if (!is_interrupt_enable(spi_conf)) {
        SPI_ERR("interrupt is disable");
        ret = SPI_RET_FAIL;
        goto fail;
    }
#endif
    ret = spi_mode_judge_and_process(xfer, chip_config, spi_conf);
    if (ret == SPI_RET_FAIL)
        goto fail;

    ret = spi_pasue_status_judge_and_process(chip_config, spi_conf);
    if (ret == SPI_RET_FAIL)
        goto fail;

    speed = get_spi_speed(spi_conf);
    if (speed == 0) {
        SPI_ERR("speed is 0, error");
        ret = SPI_RET_FAIL;
        goto fail;
    }

#ifdef SPI_TRANSFER_POLLING
    spi_irq_handler(spi_conf);
#endif

    if ((get_pause_status(spi_conf) == PAUSED) && (spi_conf->is_last_xfer == 1))
        clear_resume_bit(spi_conf);

    return SPI_RET_SUCCESS;
fail:
    set_pause_status(IDLE, spi_conf);
    set_irq_flag(IRQ_IDLE, spi_conf);
    reset_spi(spi_conf);
    return ret;
}

static int spi_transfer_func(struct spi_transfer *xfer, struct spi_user_conf *spi_conf)
{
    int ret;
    int i = 0;
    struct mt_chip_conf *chip_config = NULL;

    /* wait intrrupt had been clear */
    while (get_irq_flag(spi_conf) == IRQ_BUSY) {
        if (i >= SPI_TRANSFER_LIMIT_TIME) {
            SPI_ERR("Has already waited IRQFLAG for %d ms\n", i);
            set_irq_flag(IRQ_IDLE, spi_conf);
            return SPI_RET_FAIL;
        }
        i++;
    }
    /* set flag to block next transfer */
    set_irq_flag(IRQ_BUSY, spi_conf);

    if (xfer == NULL) {
        SPI_ERR("the message is NULL");
        return SPI_RET_FAIL;
    }

    if (!((xfer->tx_buf || xfer->rx_buf) && xfer->len)) {
        SPI_ERR("missing tx %p or rx %p buf, len%u", xfer->tx_buf, xfer->rx_buf, xfer->len);
        return SPI_RET_FAIL;
    }

    chip_config = spi_conf->chip_config;
    if (chip_config == NULL) {
        SPI_ERR("spi_next_message get chip_config is NULL");
        set_irq_flag(IRQ_IDLE, spi_conf);
        return SPI_RET_FAIL;
    }
    spi_setup(chip_config, spi_conf);

    ret = spi_next_xfer(xfer, spi_conf);

    return ret;
}

static void set_spi_mode(int len, unsigned int flag, struct spi_transfer *spi_data)
{
    if (len > FIFO_MAX_LEN) {
        spi_data->is_dma_used = 1;
        spi_data->chip_config->com_mod = DMA_TRANSFER;
    } else {
        spi_data->is_dma_used = 0;
        spi_data->chip_config->com_mod = FIFO_TRANSFER;
    }

    spi_data->is_transfer_end = flag;
}

static int spi_transfer_handle(struct spi_transfer *spi_data, struct spi_user_conf *spi_conf,
    unsigned int flag, const void *tx_buf, void *rx_buf)
{
    int ret;
    unsigned int packet_loop = spi_data->len / SPI_1K;
    unsigned int rest_size = spi_data->len % SPI_1K;

#ifdef SPI_TEST
    spi_enable_clk(spi_conf);
#endif
    if ((spi_data->len <= SPI_1K) || (rest_size == 0)) {
        SPI_DBG("Signal transfer start,len:%u", spi_data->len);
        ret = spi_transfer_func(spi_data, spi_conf);
        return ret;
    }
    /* first transfer SPI_1K*packet_loop */
    spi_conf->chip_config->pause = 1;
    spi_conf->is_last_xfer = 0;
    spi_data->len = SPI_1K * packet_loop;

    SPI_DBG("Twice transfer,first len:%u", spi_data->len);
    ret = spi_transfer_func(spi_data, spi_conf);
    if (ret)
        return ret;

    /* then transfer reset_size byte */
    spi_data->is_transfer_end = (flag == 1) ? 0 : 1;

    spi_conf->is_last_xfer = 1;
    spi_data->is_transfer_end = 1;
    spi_data->tx_buf = (tx_buf + SPI_1K * packet_loop);
    spi_data->rx_buf = (rx_buf + SPI_1K * packet_loop);
    spi_data->len = rest_size;
    SPI_DBG("Twice transfer,first len:%u", spi_data->len);
    ret = spi_transfer_func(spi_data, spi_conf);
    return ret;
}

int spi_send(const void *tx_buf, void *rx_buf, unsigned int len, struct mt_chip_conf *chip_conf,
    struct spi_user_conf *spi_conf)
{
    struct spi_transfer spi_data;
    int ret;
    struct mt_chip_conf chip_conf_def;
    unsigned int flag;

    if (tx_buf == NULL || rx_buf == NULL || spi_conf == NULL || chip_conf == NULL) {
        SPI_ERR("input para is NULL");
        return SPI_RET_FAIL;
    }
    (void)memset_s(&spi_data, sizeof(spi_data), 0, sizeof(spi_data));
    ret = memcpy_s(&chip_conf_def, sizeof(chip_conf_def), &g_mt_chip_conf_def, sizeof(g_mt_chip_conf_def));
    if (ret != 0)
        SPI_ERR("memcpy_s chip_conf_def failed");

    spi_data.tx_buf = tx_buf;
    spi_data.rx_buf = rx_buf;
    spi_data.len = len;
    flag = spi_conf->flag;

    SPI_DBG("g_spi_tx_dma_va is %x g_spi_rx_dma_va is %x", spi_conf->spi_tx_dma_va, spi_conf->spi_rx_dma_va);

    spi_data.chip_config = (chip_conf != NULL) ? chip_conf : &chip_conf_def;

    SPI_DBG("spi%d com_mod:%d, len:%d", spi_conf->spi_id, spi_data.chip_config->com_mod, len);

    set_spi_mode(len, flag, &spi_data);
    /* chip_conf or chip_conf_def is unuseable after gave value to spi_conf->chip_config */
    set_chip_config(spi_data.chip_config, spi_conf);
    set_spi_transfer(&spi_data, spi_conf);

    ret = spi_transfer_handle(&spi_data, spi_conf, flag, tx_buf, rx_buf);

    return ret;
}

static int spi_map_register(enum spi_protect_index spi_id, struct spi_user_conf *spi_conf)
{
    if (spi_id >= SPI_NUM) {
        SPI_ERR("spi %d is not defined", spi_id);
        return SPI_RET_FAIL;
    }
    spi_conf->spi_base_va = g_spi_addr[spi_id];
    spi_conf->spi_pdn_base_va = SPI_PDN_PA_BASE;

    return SPI_RET_SUCCESS;
}

static int spi_dma_addr_get_and_map(struct spi_user_conf *spi_conf, uint32_t spi_dma_phy_addr)
{
    unsigned char *tmp_dma_va = NULL;

    tmp_dma_va = (unsigned char *)malloc_coherent((DMA_SIZE + DMA_ALIGN_SIZE));
    if (tmp_dma_va == NULL) {
        SPI_ERR("malloc dma buffer failed");
        return SPI_RET_FAIL;
    }

    spi_conf->chip_config = malloc_coherent(sizeof(struct mt_chip_conf));
    if (spi_conf->chip_config == NULL) {
        SPI_ERR("g_chip_config malloc failed");
        free(tmp_dma_va);
        tmp_dma_va = NULL;
        return SPI_RET_FAIL;
    }

    spi_conf->spi_tx_dma_va = (unsigned char *)ALIGN_UP((u32)tmp_dma_va, DMA_ALIGN_SIZE);

    spi_conf->spi_rx_dma_va = spi_conf->spi_tx_dma_va + SPI_128K;
    SPI_DBG("g_spi_tx_dma_va is %x g_spi_rx_dma_va is %x", spi_conf->spi_tx_dma_va, spi_conf->spi_rx_dma_va);

    spi_conf->spi_tx_dma_ph_addr = (u32)virt_mem_to_phys((uintptr_t)spi_conf->spi_tx_dma_va);
    spi_conf->spi_rx_dma_ph_addr = (u32)virt_mem_to_phys((uintptr_t)spi_conf->spi_rx_dma_va);

    spi_conf->spi_tx_dma_ph_addr = spi_dma_phy_addr;
    spi_conf->spi_rx_dma_ph_addr = spi_dma_phy_addr + DMA_SIZE;

    if (sre_mmap((paddr_t)spi_conf->spi_tx_dma_ph_addr, DMA_SIZE, (unsigned int *)(&spi_conf->spi_tx_dma_va),
        secure, non_cache))
        SPI_ERR("mmap failed1\n");

    if (sre_mmap((paddr_t)spi_conf->spi_rx_dma_ph_addr, DMA_SIZE, (unsigned int *)(&spi_conf->spi_rx_dma_va),
        secure, non_cache))
        SPI_ERR("mmap failed2\n");

    SPI_DBG("spi%d spi_tx_dma_va is %x spi_rx_dma_va is %x\n",
        spi_conf->spi_id, spi_conf->spi_tx_dma_va, spi_conf->spi_rx_dma_va);
    SPI_DBG("spi%d spi_tx_dma_pa is %x spi_rx_dma_pa is %x",
        spi_conf->spi_id, spi_conf->spi_tx_dma_ph_addr, spi_conf->spi_rx_dma_ph_addr);

    return SPI_RET_SUCCESS;
}

int spi_init(enum spi_protect_index spi_id, uint32_t spi_dma_phy_addr, struct spi_user_conf *spi_conf)
{
    int ret = SPI_RET_FAIL;

    SPI_ERR("spi_init enter spi%d, spi_dma_phy_addr 0x%x", spi_id, spi_dma_phy_addr);
    if (spi_conf == NULL || spi_id < 0 || spi_id >= SPI_NUM) {
        SPI_ERR("%s param error:%d", __func__, spi_id);
        return ret;
    }
    spi_conf->spi_id = spi_id;
    ret = spi_dma_addr_get_and_map(spi_conf, spi_dma_phy_addr);
    if (ret) {
        SPI_ERR("%s spi get and map DMA addr fail,ret:%d", __func__, ret);
        return ret;
    }

    ret = spi_map_register(spi_id, spi_conf);
    if (ret) {
        SPI_ERR("%s spi map reg fail,ret:%d", __func__, ret);
        return ret;
    }
    set_irq_flag(IRQ_IDLE, spi_conf);
    reset_spi(spi_conf);
    spi_conf->is_last_xfer = 1;
    SPI_DBG("spi_init exit");
    return ret;
}

void spi_exit(struct spi_user_conf *spi_conf)
{
    if (sre_unmap(*((unsigned int *)(&spi_conf->spi_tx_dma_va)), DMA_SIZE))
        SPI_ERR("unmap failed1\n");

    if (sre_unmap(*((unsigned int *)(&spi_conf->spi_rx_dma_va)), DMA_SIZE))
        SPI_ERR("unmap failed2\n");
}

/* get_spi_dma_addr used by ese and tee_fingerprint */
uint64_t get_spi_dma_addr(void)
{
    struct tee_spi_info_t spi_info;
    int ret = (UINT32)get_shared_mem_info(TEEOS_SHARED_MEM_SPI_DMA_BUF, (unsigned int *)&spi_info,
                                          sizeof(struct tee_spi_info_t));
    if (ret != 0) {
        SPI_ERR("get spi_dma_phy_addr failed\n");
        return INVALID_DMA_ADDRESS;
    }

    return spi_info.spi_addr;
}

int spi_dev_init(void)
{
    SPI_ERR("spi_dev_init enter");
    return 0;
}

DECLARE_TC_DRV(
    spi,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    spi_dev_init,
    NULL,
    NULL,
    NULL,
    NULL
);
