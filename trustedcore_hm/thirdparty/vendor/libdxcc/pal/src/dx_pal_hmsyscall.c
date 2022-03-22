__attribute__((weak)) void *memmove(void *dest, const void *src, unsigned long n)
{
    unsigned long i = 0;

    for (i = 0; i < n; i++) {
        *(char *)dest = *(const char *)src;
        (char *)dest++;
        (char *)src++;
    }

    return dest;
}

void dx_abort(void)
{
    printf("DX_PAL abort called!\n");
    *((int *)0) = 0; // make it panic, and print dump stack
	while(1);
}
