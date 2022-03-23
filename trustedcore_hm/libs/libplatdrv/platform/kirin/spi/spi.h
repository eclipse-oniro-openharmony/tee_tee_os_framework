#ifndef __SPI_HISI_H_
#define __SPI_HISI_H_

#include "hisi_boot.h"
#include "soc_acpu_baseaddr_interface.h"


#define REG_BASE_SPI0               SOC_ACPU_IOMCU_SPI0_BASE_ADDR
#define REG_BASE_SPI1               SOC_ACPU_SPI1_BASE_ADDR
#define REG_BASE_SPI2               SOC_ACPU_IOMCU_SPI2_BASE_ADDR
#define REG_BASE_SPI3               SOC_ACPU_SPI3_BASE_ADDR
#define REG_BASE_SPI4               SOC_ACPU_SPI4_BASE_ADDR

#define SPI_OK 0
#define SPI_ERR 1

#define SPI_TRUE 1
#define SPI_FALSE 0

#define SPI_CPHA 0x01
#define SPI_CPOL 0x02

#define SPI_MODE_0 (0 | 0)
#define SPI_MODE_1 (0 | SPI_CPHA)
#define SPI_MODE_2 (SPI_CPOL | 0)
#define SPI_MODE_3 (SPI_CPOL | SPI_CPHA)

#define SPI_LOOP 0x20

enum ssp_data_size {
	SSP_DATA_BITS_4 = 0x03,
	SSP_DATA_BITS_5,
	SSP_DATA_BITS_6,
	SSP_DATA_BITS_7,
	SSP_DATA_BITS_8,
	SSP_DATA_BITS_9,
	SSP_DATA_BITS_10,
	SSP_DATA_BITS_11,
	SSP_DATA_BITS_12,
	SSP_DATA_BITS_13,
	SSP_DATA_BITS_14,
	SSP_DATA_BITS_15,
	SSP_DATA_BITS_16,
	SSP_DATA_BITS_17,
	SSP_DATA_BITS_18,
	SSP_DATA_BITS_19,
	SSP_DATA_BITS_20,
	SSP_DATA_BITS_21,
	SSP_DATA_BITS_22,
	SSP_DATA_BITS_23,
	SSP_DATA_BITS_24,
	SSP_DATA_BITS_25,
	SSP_DATA_BITS_26,
	SSP_DATA_BITS_27,
	SSP_DATA_BITS_28,
	SSP_DATA_BITS_29,
	SSP_DATA_BITS_30,
	SSP_DATA_BITS_31,
	SSP_DATA_BITS_32
};

enum ssp_spi_clk_pol { SSP_CLK_POL_IDLE_LOW, SSP_CLK_POL_IDLE_HIGH };

// whether SSP is in loopback mode or not
enum ssp_loopback { LOOPBACK_DISABLED, LOOPBACK_ENABLED };

enum ssp_chip_select { SSP_CHIP_SELECT, SSP_CHIP_DESELECT };

enum ssp_rx_level_trig {
	SSP_RX_1_OR_MORE_ELEM,
	SSP_RX_4_OR_MORE_ELEM,
	SSP_RX_8_OR_MORE_ELEM,
	SSP_RX_16_OR_MORE_ELEM,
	SSP_RX_32_OR_MORE_ELEM,
	SSP_RX_64_OR_MORE_ELEM,
	SSP_RX_128_OR_MORE_ELEM,
	SSP_RX_224_OR_MORE_ELEM
};

enum ssp_tx_level_trig {
	SSP_TX_16_OR_MORE_EMPTY_LOC = 3,
};

enum ssp_spi_clk_phase { SSP_CLK_FIRST_EDGE, SSP_CLK_SECOND_EDGE };

enum ssp_hierarchy { SSP_MASTER, SSP_SLAVE };

struct ssp_clock_params {
	u8 cpsdvsr; /* value from 2 to 254 (even only!) */
	u8 scr;     /* value from 0 to 255 */
};

struct spi_config_chip {
	enum ssp_hierarchy hierarchy;
	bool slave_tx_disable;
	struct ssp_clock_params clk_freq;
	void (*cs_control)(u32 control);
};

struct spi_device {
	u32 max_speed_hz;
	u8 mode;
	u8 bits_per_word;
	void *controller_data;
};

struct spi_transfer {
	const void *tx_buf;
	void *rx_buf;
	unsigned int len;

	unsigned cs_change : 1;
	u16 delay_usecs;

	struct list_head transfer_list;
};

struct spi_message {
	struct list_head transfer;

	struct spi_transfer *transfers;
	unsigned int transfer_num;
	unsigned int actual_length;
	int status;
};

struct spi_seq {
	struct spi_device spi;
	void (*cs_control)(u32 control);
	const void *tx;
	u32 tx_len;
	void *rx;
	u32 rx_len;
};

int hisi_spi_dma_transfer(const u32 chip_addr, struct spi_message *msg);
int hisi_spi_polling_transfer(const u32 chip_addr, struct spi_message *msg);
int hisi_spi_init(const u32 chip_addr, struct spi_device *spi);
void hisi_spi_exit(const u32 chip_addr);

/*The following functions do not support the transfer of DMA*/
int spi_dev_read(struct spi_seq *seq, const u32 chip_addr);
int spi_dev_write(struct spi_seq *seq, const u32 chip_addr);
int spi_read(struct spi_device *spi, void *buf, unsigned int len,
	const u32 chip_addr);
int spi_write(struct spi_device *spi, const void *buf, unsigned int len,
	const u32 chip_addr);
int spi_write_then_read(struct spi_device *spi, const void *txbuf,
	unsigned int n_tx, void *rxbuf, unsigned int n_rx, const u32 chip_addr);

extern void v7_flush_kern_cache_all(void);
extern void v7_dma_map_area(const void *buf, unsigned long len, int type);
extern void v7_dma_unmap_area(const void *buf, unsigned long len, int type);
extern void uart_printf_func(const char *fmt, ...);

#endif
