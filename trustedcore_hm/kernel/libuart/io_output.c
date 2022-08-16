/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: uart output function
 * Create: 2020-12
 */
#include <config.h>
#include <machine/io.h>
#include <uart_register.h>

#ifdef CONFIG_PRINTING

#include <stdarg.h>
#include <kernel/spinlock.h>

/* put a char for printing */
static void put_console_char(unsigned char c)
{
    put_debug_char(c);
}

/* put a char to console */
void putchar(char c)
{
    put_console_char((unsigned char)c);
    if (c == '\n')
        put_console_char('\r');
}

static unsigned int print_string(const char *s)
{
    unsigned int n;

    for (n = 0; *s != '\0'; s++, n++)
        kernel_putchar(*s);

    return n;
}

#define HEXADECIMAL_LEN 20
static const char g_hexadecimal_base[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

/*
 * all callers are in this file and base is only 10 or 16 in each caller
 * print a number in base 10 or 16
 * ch [len++] and ch[i - 1] is valid because
 * the largest 64-bits unsigned integer has only 20 bits with base 10
 * */
static ulong_t print_unsigned_long(unsigned long x, ulong_t base)
{
    char ch[HEXADECIMAL_LEN];
    ulong_t len = 0;
    ulong_t i;

    /* only print in base 10 and 16 */
    if (base != 10 && base != 16)
        return 0;

    do {
        unsigned long rest;

        rest = x % base;
        x /= base;
        ch[len++] = g_hexadecimal_base[rest];
    } while (x != 0UL && len < HEXADECIMAL_LEN);

    for (i = len; i > 0; --i)
        kernel_putchar(ch[i - 1]);

    return len;
}

/*
 * The print_unsigned_long_long function assumes that an unsinged int
 * is half the size of an unsigned long long
 */
compile_assert(print_unsigned_long_long_sizes,
               sizeof(unsigned int) * 2 == sizeof(unsigned long long))

/*
 * ARG: base: internal, only callers is vprintf in this file and
 * base is only 16 checked here.
 */
static ulong_t print_unsigned_long_long(unsigned long long x, ulong_t base)
{
    unsigned int left = (unsigned int)(x >> 32ULL);
    unsigned int right = (unsigned int)(x & 0xffffffffULL);
    unsigned long len = 0;
    unsigned int i = 0;

    /* only print in base 16 */
    if (base != 16)
        return 0;
    if (left) {
        len += print_unsigned_long(left, base);
        i = 28U;
        while ((right & (0xfU << i)) == 0U  && i >= 4U) {
            kernel_putchar('0');
            ++len;
            i -= 4U;
        }
    }
    len += print_unsigned_long(right, base);
    return len;
}

static HM_SPINLOCK(console_lock);
/*
 * this is a simple implementation
 * of the printf functionality
 *
 * supported formats are :
 * %d, %u, %x, %p, %s,
 * %ld, %llx, %lu, %lx
 *
 * other output formats and controlling
 * functionality are not supported yet.
 */
static ulong_t vprintf(const char *format, va_list ap)
{
    unsigned long irq_flags;
    unsigned int tag = 0;
    ulong_t len = 0;
    int i;
    unsigned long ul;
    long l;
    char *pchar = NULL;

    if (format == NULL)
        return 0;

    /* console_lock is initialized above */
    irq_flags = hm_spinlock_acquire_irqsave(&console_lock);

    while (*format) {
        if (tag) {
            switch (*format) {
            case '%':
                kernel_putchar('%');
                ++len;
                ++format;
                break;

            case 'd': {
                i = va_arg(ap, int);
                if (i < 0) {
                    kernel_putchar('-');
                    ++len;
                    i = -i;
                }
                len += print_unsigned_long(i, 10);
                ++format;
                break;
            }

            case 'u':
                len += print_unsigned_long(va_arg(ap, unsigned int), 10);
                ++format;
                break;

            case 'x':
                len += print_unsigned_long(va_arg(ap, unsigned int), 16);
                ++format;
                break;

            case 'p': {
                ul = va_arg(ap, unsigned long);
                if (ul == 0) {
                    len += print_string("(nil)");
                } else {
                    len += print_string("0x");
                    len += print_unsigned_long(ul, 16);
                }
                ++format;
                break;
            }

            case 's':
                pchar = va_arg(ap, char *);
                /* gatantee not to read from NULL */
                if (pchar == NULL) {
                    hm_spinlock_release_irqrestore(&console_lock, irq_flags);
                    return -1;
                }
                len += print_string(pchar);
                ++format;
                break;

            case 'l':
                ++format;
                switch (*format) {
                case 'd': {
                    l = va_arg(ap, long);
                    if (l < 0) {
                        kernel_putchar('-');
                        l = -l;
                        ++len;
                    }
                    len += print_unsigned_long((unsigned long)l, 10);
                    ++format;
                }
                break;
                case 'l':
                    if (*(format + 1) == 'x') {
                        len += print_unsigned_long_long(va_arg(ap, unsigned long long), 16);
                    } else {
                        hm_spinlock_release_irqrestore(&console_lock, irq_flags);
                        return -1;
                    }
                    format += 2;
                    break;
                case 'u':
                    len += print_unsigned_long(va_arg(ap, unsigned long), 10);
                    ++format;
                    break;
                case 'x':
                    len += print_unsigned_long(va_arg(ap, unsigned long), 16);
                    ++format;
                    break;

                default:
                    hm_spinlock_release_irqrestore(&console_lock, irq_flags);
                    return -1;
                }
                break;
            default:
                hm_spinlock_release_irqrestore(&console_lock, irq_flags);
                return -1;
            }
            tag = 0;
        } else {
            switch (*format) {
            case '%':
                tag = 1;
                break;

            default:
                kernel_putchar(*format);
                ++len;
                break;
            }
            ++format;
        }
    }

    hm_spinlock_release_irqrestore(&console_lock, irq_flags);
    return len;
}

int32_t puts(const char *s)
{
    unsigned long irq_flags;

    if (s == NULL)
        return -1;

    irq_flags = hm_spinlock_acquire_irqsave(&console_lock);
    for (; *s != '\0'; s++)
        kernel_putchar(*s);
    kernel_putchar('\n');
    hm_spinlock_release_irqrestore(&console_lock, irq_flags);
    return 0;
}

/* print with format string */
ulong_t kprintf(const char *format, ...)
{
    va_list args;
    ulong_t i;

    va_start(args, format);
    i = vprintf(format, args);
    va_end(args);
    return i;
}

#endif
