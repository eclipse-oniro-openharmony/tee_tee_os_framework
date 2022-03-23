#ifndef _NPU_PUBLIC_SEC_H
#define _NPU_PUBLIC_SEC_H

// #define DEBUG_PRINT

void uart_printf_func(const char *fmt, ...);
#define NPU_PRINT(string, arg...)  uart_printf_func("[%s][%d]:" string "\n", __func__, __LINE__, ##arg)
#define NPU_ERR(string, arg...)    uart_printf_func("[%s][%d]:NPU_ERROR: " string "\n", __func__, __LINE__, ##arg)

#ifdef DEBUG_PRINT
#define NPU_DEBUG(string, arg...)  uart_printf_func("[%s][%d]: " string  "\n", __func__, __LINE__, ##arg)
#else
#define NPU_DEBUG(string, ...)
#endif

typedef enum {
    NPU_CORE_0,
    NPU_CORE_1,
    MAX_SUPPORT_CORE_NUM,
} NPU_CORE_ID_E;

#define UNUSED_PARAMETER(x) ((void)(x))

#define PLATFORM_VERSION  0x00100001
#define NPU_VERSION_V200  0x00010000
#define NPU_VERSION_V150  0x00000000

#define VERSION_V200

#ifdef VERSION_V150
#define HARD_VERSION NPU_VERSION_V150
#else
#define HARD_VERSION NPU_VERSION_V200
#endif

#define NPU_TO_STOP          0x0
#define NPU_TO_START         0x1

/* NPU start up reg */
#define NPU_START_REG        0x18
/* NPU payload finish status reg */
#define NPU_STATUS_REG       0x20
/* NPU access external DDR address */
#define NPU_BASE_ADDR_REG    0x28
/* NPU internal SRAM configure reg */
#define NPU_SRAM_CTRL_REG    0x30
/* NPU Version reg */
#define NPU_VERSION_REG      0x40

#define NPU_STATUS_UNFINISH  0x0

#define NPU_IRQ_CLEAR_IRQ_S  0x00000001
#define NPU_IRQ_CLEAR_IRQ_LEVEL1_S 0x2

void npu_reg_bit_write_dword
(
    unsigned int reg_addr,
    unsigned int start_bit,
    unsigned int end_bit,
    unsigned int content
);

#endif
