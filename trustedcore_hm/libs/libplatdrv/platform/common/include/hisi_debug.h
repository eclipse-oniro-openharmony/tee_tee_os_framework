#ifndef __HISI_DEBUG_H__
#define __HISI_DEBUG_H__

extern void uart_printf_func(const char *fmt, ...);

#define HISI_DEBUG_ENABLE (0x1 << 0)
#define HISI_INFO_ENABLE (0x1 << 1)
#define HISI_WARRING_ENABLE (0x1 << 2)
#define HISI_ERROR_ENABLE (0x1 << 3)
#define HISI_ASSERT_ENABLE (0x1 << 4)

#define HISI_PRINT_FLAG                                                        \
	(HISI_WARRING_ENABLE | HISI_ERROR_ENABLE | HISI_ASSERT_ENABLE)

#if (HISI_PRINT_FLAG & HISI_DEBUG_ENABLE)
#define HISI_PRINT_DEBUG uart_printf_func
#else
#define HISI_PRINT_DEBUG(exp, ...) {}
#endif

#if (HISI_PRINT_FLAG & HISI_INFO_ENABLE)
#define HISI_PRINT_INFO uart_printf_func
#else
#define HISI_PRINT_INFO(exp, ...) {}
#endif

#if (HISI_PRINT_FLAG & HISI_WARRING_ENABLE)
#define HISI_PRINT_WARRING uart_printf_func
#else
#define HISI_PRINT_WARRING(exp, ...) {}
#endif

#if (HISI_PRINT_FLAG & HISI_ERROR_ENABLE)
#define HISI_PRINT_ERROR uart_printf_func
#else
#define HISI_PRINT_ERROR(exp, ...) {}
#endif

#if (HISI_PRINT_FLAG & HISI_ASSERT_ENABLE)
#define HISI_ASSERT(cond, exp)                                                 \
	if (!(cond)) {                                                         \
		uart_printf_func((char *)exp);                                 \
		while (TRUE)                                                   \
			;                                                      \
	}
#else
#define HISI_ASSERT(cond, exp)
#endif

#endif
