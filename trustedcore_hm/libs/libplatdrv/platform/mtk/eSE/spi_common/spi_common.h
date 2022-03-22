 /*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: eSE SPI comon opration.
 * Author: w00271044
 * Create: 2020-07-28
 */

#ifndef _SPI_COMMON_H_
#define _SPI_COMMON_H_
#include "spi.h"

#define SPI_ALIGN_4_SIZE(X)    ((X) % 4 ? ((X) + 4) - ((X) & (0x3)) : (X))
#define SPI_ALIGN_1024_SIZE(X) (((X) % 1024 && (X) > 1024) ? ((X) + 1024) - ((X) % 1024) : (X))
#define ESE_RET_SUCCESS 0
#define ESE_RET_FAIL (-1)

#define ese_check_ret(ret) do {                                                                   \
    if ((ret) != 0) {                                                                            \
        tloge("%s: %d: memcpy_s failed! ret = %d\n", __func__, __LINE__, (ret));      \
    }                                                                                            \
} while (0)

#define pointer_free(ptr) do { \
    if ((ptr) != NULL) {       \
        free(ptr);             \
        (ptr) = NULL;          \
    }                          \
} while (0)

struct spi_transaction_info {
    unsigned char *reg_addr;
    unsigned char *buf_addr;
    unsigned int reg_len;
    unsigned int buf_len;
};

int ese_spi_driver_value_init(void **tx_buff, void **rx_buff, uint32_t align_buff_size);
int ese_set_spi_dma_permisson(enum devapc_master_req_type devapc_master_req,
    enum devapc_protect_on_off devapc_protect, enum spi_protect_index spi);
int ese_driver_spi_full_duplex(struct spi_transaction_info *write_info, struct spi_transaction_info *read_info);
#endif
