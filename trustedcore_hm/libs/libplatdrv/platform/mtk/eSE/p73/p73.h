#ifndef __P73_SE_H
#define __P73_SE_H
#endif

#define MEM_DATA_SIZE 8
#define ESE_MAGIC_NUM  0x66BB
#define OFFSET_8       8
#define OFFSET_16      16

int p61_dev_write(const char  *buf,int count);
int p61_dev_read(char  *buf, int count);
void p73_load_config(void);
