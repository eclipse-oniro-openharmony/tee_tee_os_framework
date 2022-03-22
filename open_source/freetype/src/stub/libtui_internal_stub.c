#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define FT_FILE int

long ft_ftell(FT_FILE *fd)
{
    return (long)0;
}

FT_FILE *ft_fopen(const char *name, char *flag)
{
    return NULL;
}

int ft_fread(char *buffer, int len, int numbers, FT_FILE *fd)
{
    return 0;
}

int ft_fseek(FT_FILE *stream, long offset, int whence)
{
    return 0;
}


int ft_fclose(FT_FILE *fd)
{
    return 0;
}
unsigned char *ftmalloc(unsigned int sz)
{
    unsigned char *c = malloc(sz);
    return c;
}
void ftfree(void *FirstByte)
{
    unsigned char *p = FirstByte;
    free(p);
}
