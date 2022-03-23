#ifndef __SEC_HISI_DMA_
#define __SEC_HISI_DMA_

#include <mem_ops.h>
#include "hisi_boot.h"

enum hisi_dma_dir {
	HISI_DMA_TX = 6,
	HISI_DMA_RX,
};

struct hisi_dma_des {
	enum hisi_dma_dir dir;
	void *src;
	void *dst;
	u32 len;
	u32 req_no;
};

#define DMA_TO_DEVICE 1
#define DMA_FROM_DEVICE 2

#if ((TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI3650) && \
	(TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI6250) && \
	(TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI3660))
int hisi_dma_init(void);
int hisi_dma_process_status(void);
int hisi_dma_config_check(void);
int hisi_dma_config(struct hisi_dma_des *dma_des);
void hisi_dma_start(void);
void hisi_dma_exit(void);
#else
int hisi_dma_process_status(void)
{
	return -1;
}
int hisi_dma_config_check(void)
{
	return -1;
}
int hisi_dma_config(struct hisi_dma_des *dma_des)
{
	return -1;
}
int hisi_dma_start(void)
{
	return -1;
}
int hisi_dma_stop(void)
{
	return -1;
}
#endif

extern void *malloc_coherent(size_t n);
extern void uart_printf_func(const char *fmt, ...);
#endif
