#include <string.h>
#include <stdint.h>
#include <endian.h>

void *asm_memcpy(void *restrict dest, const void *restrict src, size_t n)
{
    return memcpy(dest, src, n);
}
