/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: MTK SPI Define Header File
 * Author: tangjianbo
 * Create: 2020-01-21
 */
#ifndef SPI_H
#define SPI_H

typedef unsigned int uint32_t;
typedef signed int int32_t;
typedef unsigned char uint8_t;
typedef unsigned long long uint64_t;

#define FIFO_MAX_LEN        32
#define DMA_SIZE            (256 * 1024)
#define PACKET_SIZE         0x400

#define IDLE                0
#define INPROGRESS          1
#define PAUSED              2
#define INVALID_DMA_ADDRESS 0xffffffff

#define MTK_SIP_TEE_APC_MODULE_SET_AARCH32      0x82000040
#define MTK_SIP_TEE_APC_MODULE_SET_AARCH64      0xC2000040
#define MTK_SIP_TEE_APC_MM2ND_SET_AARCH32       0x82000041
#define MTK_SIP_TEE_APC_MM2ND_SET_AARCH64       0xC2000041
#define MTK_SIP_TEE_APC_MASTER_SET_AARCH32      0x82000042
#define MTK_SIP_TEE_APC_MASTER_SET_AARCH64      0xC2000042
#define MTK_SIP_TEE_HAL_APC_SET_AARCH32         0x82000043
#define MTK_SIP_TEE_HAL_APC_SET_AARCH64         0xC2000043
#define MTK_SIP_TEE_HAL_MASTER_TRANS_AARCH32    0x82000044
#define MTK_SIP_TEE_HAL_MASTER_TRANS_AARCH64    0xC2000044

enum spi_cpol {
    SPI_CPOL_0,
    SPI_CPOL_1
};

enum spi_cpha {
    SPI_CPHA_0,
    SPI_CPHA_1
};

enum spi_mlsb {
    SPI_LSB,
    SPI_MSB
};

enum spi_endian {
    SPI_LENDIAN,
    SPI_BENDIAN
};

enum spi_transfer_mode {
    FIFO_TRANSFER,
    DMA_TRANSFER,
};

enum spi_pause_mode {
    PAUSE_MODE_DISABLE,
    PAUSE_MODE_ENABLE
};
enum spi_finish_intr {
    FINISH_INTR_DIS,
    FINISH_INTR_EN,
};

enum spi_deassert_mode {
    DEASSERT_DISABLE,
    DEASSERT_ENABLE
};

enum spi_ulthigh {
    ULTRA_HIGH_DISABLE,
    ULTRA_HIGH_ENABLE
};

enum spi_tckdly {
    TICK_DLY0,
    TICK_DLY1,
    TICK_DLY2,
    TICK_DLY3
};

enum spi_irq_flag {
    IRQ_IDLE,
    IRQ_BUSY
};

struct hieps_smc_atf {
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
};

enum devapc_master_req_type {
    DEVAPC_MASTER_REQ_SPI,
    DEVAPC_MASTER_REQ_NUM,
};

enum devapc_protect_on_off {
    DEVAPC_PROTECT_DISABLE = 0,
    DEVAPC_PROTECT_ENABLE,
};

enum spi_protect_index {
    SPI0 = 0,
    SPI1,
    SPI2,
    SPI3,
    SPI4,
    SPI5,
    SPI6,
    SPI7,
    SPI_NUM,
};

enum spi_reg_index {
    REG_CFG0 = 0,
    REG_CFG1,
    REG_TX_SRC,
    REG_RX_DST,
    REG_TX_DATA,
    REG_RX_DATA,
    REG_CMD,
    REG_STATUS0,
    REG_STATUS1,
    REG_PAD_SEL,
    REG_CFG2,
    REG_TX_SRC_64,
    REG_RX_DST_64,
    REG_MAX,
};

enum spi_pdn_index {
    PDN_SET = 0,
    PDN_CLR,
    PDN_STA,
    PDN_MAX,
};

struct mt_chip_conf {
    uint32_t setup_time;
    uint32_t hold_time;
    uint32_t high_time;
    uint32_t low_time;
    uint32_t cs_idle_time;
    uint32_t ulthgh_thrsh;
    enum spi_cpol cpol;
    enum spi_cpha cpha;
    enum spi_mlsb tx_mlsb;
    enum spi_mlsb rx_mlsb;
    enum spi_endian tx_endian;
    enum spi_endian rx_endian;
    enum spi_transfer_mode com_mod;
    enum spi_pause_mode pause;
    enum spi_finish_intr finish_intr;
    enum spi_deassert_mode deassert;
    enum spi_ulthigh ulthigh;
    enum spi_tckdly tckdly;
};

struct tee_spi_info_t {
    uint64_t spi_addr;
};

/*
 * struct spi_transfer - a read/write buffer pair
 * @tx_buf: data to be written (dma-safe memory), or NULL
 * @rx_buf: data to be read (dma-safe memory), or NULL
 * @tx_dma: DMA address of tx_buf, if @spi_message.is_dma_mapped
 * @rx_dma: DMA address of rx_buf, if @spi_message.is_dma_mapped
 * @len: size of rx and tx buffers (in bytes)
 * @speed_hz: Select a speed other than the device default for this
 *      transfer. If 0 the default (from @spi_device) is used.
 * @bits_per_word: select a bits_per_word other than the device default
 *      for this transfer. If 0 the default (from @spi_device) is used.
 * @cs_change: affects chipselect after this transfer completes
 * @delay_usecs: microseconds to delay after this transfer before
 *    (optionally) changing the chipselect status, then starting
 *    the next transfer or completing this @spi_message.
 * @transfer_list: transfers are sequenced through @spi_message.transfers
 *
 * SPI transfers always write the same number of bytes as they read.
 * Protocol drivers should always provide @rx_buf and/or @tx_buf.
 * In some cases, they may also want to provide DMA addresses for
 * the data being transferred; that may reduce overhead, when the
 * underlying driver uses dma.
 *
 * If the transmit buffer is null, zeroes will be shifted out
 * while filling @rx_buf.  If the receive buffer is null, the data
 * shifted in will be discarded.  Only "len" bytes shift out (or in).
 * It's an error to try to shift out a partial word.  (For example, by
 * shifting out three bytes with word size of sixteen or twenty bits;
 * the former uses two bytes per word, the latter uses four bytes.)
 *
 * In-memory data values are always in native CPU byte order, translated
 * from the wire byte order (big-endian except with SPI_LSB_FIRST).  So
 * for example when bits_per_word is sixteen, buffers are 2N bytes long
 * (@len = 2N) and hold N sixteen bit words in CPU byte order.
 *
 * When the word size of the SPI transfer is not a power-of-two multiple
 * of eight bits, those in-memory words include extra bits.  In-memory
 * words are always seen by protocol drivers as right-justified, so the
 * undefined (rx) or unused (tx) bits are always the most significant bits.
 *
 * All SPI transfers start with the relevant chipselect active.  Normally
 * it stays selected until after the last transfer in a message.  Drivers
 * can affect the chipselect signal using cs_change.
 *
 * (i) If the transfer isn't the last one in the message, this flag is
 * used to make the chipselect briefly go inactive in the middle of the
 * message.  Toggling chipselect in this way may be needed to terminate
 * a chip command, letting a single spi_message perform all of group of
 * chip transactions together.
 *
 * (ii) When the transfer is the last one in the message, the chip may
 * stay selected until the next transfer.  On multi-device SPI busses
 * with nothing blocking messages going to other devices, this is just
 * a performance hint; starting a message to another device deselects
 * this one.  But in other cases, this can be used to ensure correctness.
 * Some devices need protocol transactions to be built from a series of
 * spi_message submissions, where the content of one message is determined
 * by the results of previous messages and where the whole transaction
 * ends when the chipselect goes intactive.
 *
 * The code that submits an spi_message (and its spi_transfers)
 * to the lower layers is responsible for managing its memory.
 * Zero-initialize every field you don't set up explicitly, to
 * insulate against future API updates.  After you submit a message
 * and its transfers, ignore them until its completion callback.
 */
struct spi_transfer {
    uint32_t command_id;
    const void *tx_buf;
    void *rx_buf;
    uint32_t len;
    uint32_t is_dma_used;
    uint32_t is_transfer_end; /* for clear pause bit */

    uint32_t tx_dma;
    uint32_t rx_dma;

    struct mt_chip_conf *chip_config;

    int exc_flag;
};

struct spi_user_conf {
    /* if your DMA addr is reserved, these para record the PH addr and size */
    uint32_t spi_tx_dma_ph_addr;
    uint32_t spi_rx_dma_ph_addr;
    uint32_t spi_base_va; /* base address, mapped form physical address */
    uint32_t spi_pdn_base_va;
    unsigned char *spi_tx_dma_va;
    unsigned char *spi_rx_dma_va;
    struct mt_chip_conf *chip_config; /* save the chip config ,just for debug */
    struct spi_transfer *xfer; /* save the latest xfer */
    int irq_flag; /* this flag to sync every data transfer */
    int spi_running; /* spi status */
    enum spi_protect_index spi_id;
    unsigned char is_last_xfer; /* whether is last xfer, check to clear pause bit */
    unsigned int flag; /* end flag */
};

void spi_test(void);

int spi_send(const void *tx_buf, void *rx_buf, unsigned int len,
    struct mt_chip_conf *chip_conf, struct spi_user_conf *spi_conf);

int spi_init(enum spi_protect_index spi_id, uint32_t spi_dma_phy_addr, struct spi_user_conf *spi_conf);
void spi_exit(struct spi_user_conf *spi_conf);
void set_cs_bit(struct spi_user_conf *spi_conf, unsigned int value);
void set_spi5_cs(unsigned int value);
uint64_t get_spi_dma_addr(void);

#endif
