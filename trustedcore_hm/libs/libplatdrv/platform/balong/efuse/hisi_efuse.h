#ifndef _HISILICON_EFUSE_H_
#define _HISILICON_EFUSE_H_

int bsp_efuse_apb_read(u32 *pBuf, const u32 group, const u32 num);
int bsp_efuse_apb_write(u32 *pBuf, const u32 group, const u32 len);
int bsp_efuse_apb_exit_pd(void);
int bsp_efuse_aib_write(const unsigned int *buf, const unsigned int group, const unsigned int size);
int bsp_efuse_aib_read(unsigned int *buf, const unsigned int group, const unsigned int size);
int bsp_sec_efuse_write(unsigned int buffer_addr);
int bsp_sec_call_efuse_read(unsigned int buffer_addr, void *arg2, unsigned int arg3);
int bsp_sec_call_efuse_write(unsigned int buffer_addr, void *arg2, unsigned int arg3);
int bsp_sec_call_efuse_write_with_dmpu(unsigned int seckce_addr, void *arg2, unsigned int arg3);
int bsp_sec_call_efuse_sec_read(unsigned int buffer_addr, const void *arg2, unsigned int arg3);
int bsp_sec_call_efuse_sec_write(unsigned int buffer_addr, const void *arg2, unsigned int arg3);
unsigned SecBoot_get_secinfo_dieid(unsigned int *pBuffer);
int efuse_init(void);

#endif
