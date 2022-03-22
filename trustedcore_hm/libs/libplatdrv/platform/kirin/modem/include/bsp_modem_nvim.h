#ifndef __BSP_MODEM_NVIM_H__
#define __BSP_MODEM_NVIM_H__

#include <bsp_shared_ddr.h>
#include <secboot.h>

#define SHM_SIZE_NV                  (NV_DDR_SIZE)
#define SHM_MEM_NV_ADDR              ((unsigned long)SHM_BASE_ADDR + (unsigned long)SHM_OFFSET_NV)
#define SHM_MEM_NV_SIZE              (SHM_SIZE_NV)
#define NV_GLOBAL_START_ADDR         (SHM_MEM_NV_ADDR)
#define NV_GLOBAL_INFO_SIZE          ((unsigned long)0x400) /*1 K*/
#define NV_GLOBAL_CTRL_INFO_ADDR     (NV_GLOBAL_START_ADDR + (unsigned long)NV_GLOBAL_INFO_SIZE)

#define NV_MBN_NV_SIZE               ((unsigned long)1024*128)
#define NV_MBN_NV_ADDR               (SHM_MEM_NV_ADDR + (SHM_MEM_NV_SIZE - NV_MBN_NV_SIZE))
enum _file_type
{
    NV_FILE_HEAH = 0x0,
    NV_FILE_ATTRIBUTE_RESUM,
    NV_FILE_ATTRIBUTE_RDONLY,
    NV_FILE_ATTRIBUTE_RDWR,
    NV_FILE_ATTRIBUTE_MAX,
};
typedef struct nv_ctrl_file_info_stru
{
    u32  magicnum;
    u32  ctrl_size;                     /*ctrl file size*/
    u8   version[2];                    /*file version*/
    u8   modem_num;                     /*modem num*/
    u8   crc_mark;
    u32  file_offset;                   /*Offset of the File list start address*/
    u32  file_num;                      /* File num at file list*/
    u32  file_size;                     /* File list size*/
    u32  ref_offset;                    /* Offset of the NV reference data start address*/
    u32  ref_count;                     /* NV ID num*/
    u32  ref_size;                      /* NV reference data size*/
    u8   reserve2[12];
    u32  timetag[4];                    /*time stamp*/
    u32  product_version[8];            /*product version*/
}nv_ctrl_info_s;

#define NV_GLOBAL_CTRL_INFO_SIZE    (sizeof(nv_ctrl_info_s))

typedef struct nv_file_info_stru
{
    u8  file_id;             /* NV File ID */
    u8  file_type;           /* NV File type */
    u8  file_reserve[2];
    u8  file_name[20];       /* NV File Name */
    u32 file_nvnum;          /* NV File nv all num */
    u32 file_offset;         /* NV File offset*/
    u32 file_size;           /* NV File size*/
}nv_file_info_s;

void nv_set_default_info(struct secboot_info *modem_image_info);

#endif
