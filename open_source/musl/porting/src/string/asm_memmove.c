#include <string.h>
#include <stdint.h>

void *asm_memmove(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}
