/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef __SRE_SYSCASLL_EXT_H_
#define __SRE_SYSCASLL_EXT_H_

#include "mem_page_ops.h"

struct mem_map_para {
    paddr_t phy_addr;
    unsigned int size;
    unsigned int secure_mode;
    unsigned int cache_mode;
    unsigned int protect_id;
    unsigned int buff_id;
};

struct mem_unmap_para {
    unsigned int vir_addr;
    unsigned int secure_mode;
    unsigned int size;
    unsigned int protect_id;
    unsigned int buff_id;
};

struct tui_config_k;

extern unsigned int __driver_cambricon_command(void *p_cambricon_command);
#ifdef FEATURE_IRIS
extern int __iris_tee_mmap(unsigned int phy_addr, unsigned int size, unsigned int *virt_addr, unsigned int secure_mode,
                           unsigned int cache_mode);
extern int __iris_tee_unmap(unsigned int virt_addr, unsigned int size);
extern int __iris_tee_isSecureMemory(unsigned int addr, unsigned int size);
#endif
extern int __bsp_efuse_read(unsigned int *buf, const unsigned int group, const unsigned int size);
extern int __bsp_efuse_write(unsigned int *buf, const unsigned int group, const unsigned int size);
extern int __bsp_modem_call(unsigned int func_cmd, unsigned int arg1, void *arg2, unsigned int arg3);
extern UINT32 __hisi_secboot_process_soc_addr(UINT32 soc_type, const paddr_t src_addr, UINT32 process_type);
extern UINT32 __hisi_secboot_copy_img_from_os(UINT32 soc_type);
extern uint32_t __eiius_encrypto_ctr(paddr_t in_paddr, paddr_t out_paddr, uint32_t in_size, uint8_t *iv_vaddr,
                                     uint32_t iv_size, uint32_t mode);

extern uint32_t __eiius_image_verify(paddr_t data_paddr, paddr_t vrl_paddr, uint32_t maxsize, uint32_t is_decrypto);

extern uint32_t __eiius_get_paddr(uint32_t *low_paddr, uint32_t *high_paddr, uint32_t *p_size, uint32_t addr_type);

extern uint32_t __eiius_secure_memory_map(paddr_t phy_addr, unsigned int size, unsigned int *virt_addr,
                                          unsigned int secure_mode, unsigned int cache_mode);

extern uint32_t __eiius_secure_memory_unmap(unsigned int virt_addr, unsigned int size);

extern uint32_t __tee_call_hieps_drivers(uint32_t cmd, const char *input, uint32_t max_input_len, const char *parm_info,
                                         uint32_t parm_size);
/* TUI */
extern int __tui_sendevent(int type);

extern int tee_ext_get_dieid(unsigned int *buffer);
extern int __driver_dep_test();
extern int __ts_ioctl(unsigned int cmd, void *arg);

/* Face Recognize */
extern int __fr_secure_memory_map(paddr_t phy_addr, unsigned int size, unsigned int *virt_addr,
                                  unsigned int secure_mode, unsigned int cache_mode);
extern int __fr_secure_memory_unmap(unsigned int virt_addr, unsigned int size);
extern int __fr_is_secure_memory(paddr_t addr, unsigned int size, unsigned int protect_id);
extern void __fr_flush_cache(unsigned int start, unsigned int end);
extern int __fr_sion_pool_flag_set(unsigned int type);
extern int __fr_sion_pool_flag_unset(unsigned int type);
extern int __fr_get_static_phy_addr(paddr_t *addr, unsigned int type, unsigned int index, unsigned int size);

/* video decrypt */
extern int __SECURE_TEE_Mmap(struct mem_map_para *mem_para, unsigned int *virt_addr);
extern int __SECURE_TEE_Unmap(struct mem_unmap_para *mem_para);
extern int __SECURE_ISSecureMemory(paddr_t addr, unsigned int size, unsigned int protect_id);
extern void __SECURE_FlushCache(unsigned int start, unsigned int end);

extern int __driver_p61_factory_test(int reader_id);
extern int __phNxpEse_GetOsMode(void);
extern int __ese_proto7816_reset(void);
extern int __ese_set_nfc_chiptype(int chip_type);
/* display */
extern int tee_is_device_rooted(void);
extern int __driver_fingerprint_command(void *cmmand_info);
extern int __driver_spi_full_duplex(void *p_write_info, void *p_read_info);
extern int __driver_spi_full_duplex_with_speed(void *p_write_info, void *p_read_info, int speed);
extern int __driver_spi_half_duplex_with_speed(void *p_write_info, void *p_read_info, int speed);
extern int __driver_spi_dev2_full_duplex(void *p_write_info, void *p_read_info);
extern int __driver_spi_dev2_full_duplex_with_speed(void *p_write_info, void *p_read_info, int speed);
extern int __driver_spi_dev2_half_duplex_with_speed(void *p_write_info, void *p_read_info, int speed);
extern int __driver_fp_set_spi_mode(int mode);

/* rtc config */
extern unsigned int __sre_get_rtc_time();

/* skytone version api */
extern unsigned int TEE_EXT_Get_Skytone_Version();

/* hdcp */
extern int __hdcp13_key_all_set(void *key_all);
extern int __hdcp22_key_set(void *duk, void *kpf);
extern int __hdcp_dp_enable(unsigned int dp_flag);
extern int __hdcp_get_value(unsigned int offset);
extern int __hdcp_set_reg(unsigned int reg_value, unsigned int offset);
extern int __hdcp_ioctl(unsigned int cmd_id, unsigned int data, void* buf, int size);
/* hdcp for wfd */
extern int __hdcp_wfd_handle_map(unsigned int *mappedAddr, unsigned int cacheMode,
    unsigned int secShareFd, unsigned int dataLen);
extern int __hdcp_wfd_handle_unmap(unsigned int secShareFd, unsigned int dataLen);

#ifdef TEE_SUPPORT_HIVCODEC
/* hi_vcodec */
extern int __SEC_VDEC_Init(unsigned int *Args, unsigned int ArgsLen, unsigned int *phyaddrInfo, unsigned int infoLen);
extern int __SEC_VDEC_Exit(unsigned int IsSecure);
extern int __SEC_VDEC_Suspend(void);
extern int __SEC_VDEC_Resume(void);
extern int __SEC_VDEC_RunProcess(unsigned int Args, unsigned int ArgLen);
#ifdef VCODEC_ENG_VERSION
extern int __SEC_VDEC_ReadProc(unsigned int Page_h, unsigned int Page_l, int Count);
extern int __SEC_VDEC_WriteProc(unsigned int Option, int Value);
#endif
extern int __SEC_VDEC_GetChanImage(int ChanID, unsigned int *Image);
extern int __SEC_VENC_MEMTEE2REE(unsigned int nor_phy_addr, unsigned int sec_share_fd,
    unsigned int offset, unsigned int datalen);
extern int __SEC_VENC_MEMREE2TEE(unsigned int nor_phy_addr, unsigned int sec_share_fd,
    unsigned int offset, unsigned int datalen);
extern int __SEC_VENC_CFG_MASTER(unsigned int secVencState, unsigned int coreId);
extern int __SEC_VDEC_Control(int ChanID, unsigned int eCmdID, unsigned int *Args, unsigned int ArgLen,
                              unsigned int *phyaddrInfo, unsigned int infoLen);
extern int __SEC_VDEC_ReleaseChanImage(int ChanID, unsigned int *Image);
extern int __SEC_VDEC_ConfigInputBuffer(int ChanID, unsigned int *PhyAddr);
#endif

extern int __scard_connect(int reader_id, unsigned int vote_id, void *p_atr, unsigned int *atr_len);
extern int __scard_disconnect(int reader_id, unsigned int vote_id);
extern int __scard_transmit(int reader_id, unsigned char *p_cmd, unsigned int cmd_len, unsigned char *p_rsp,
                            unsigned int *rsp_len);
extern int __scard_support_mode(int reader_id);
extern int __scard_send(int reader_id, unsigned char *p_cmd, unsigned int cmd_len);
extern int __scard_receive(unsigned char *p_rsp, unsigned int *rsp_len);
extern int __scard_get_status(void);

extern int __inse_connect(void *id);
extern int __inse_disconnect(void *id);
extern int __ese_transmit_data(unsigned char *data, unsigned int data_size);
extern int __ese_read_data(unsigned char *data, unsigned int data_size);
extern int __driver_p61_factory_test(int reader_id);
extern int __phNxpEse_GetOsMode(void);
extern int __ese_proto7816_reset(void);
extern int __ese_set_nfc_chiptype(int chip_type);
extern int __scard_get_ese_type(void);

extern int __SE_setflag(int flag);
extern int __SE_getflag();

#if defined(TEE_SUPPORT_SVM) || defined(TEE_SUPPORT_SMMUV3)
extern int __teesvm_ioctl(int svm_ta_tag, void *mcl);
#endif

#ifdef TEE_SUPPORT_FILE_ENCRY
#ifdef TEE_SUPPORT_FILE_ENCRY_V2
extern INT32 __file_encry_interface(UINT32 cmd_id, UINT8 *iv_buf, UINT32 length);
#else
extern INT32 __file_encry_interface(INT32 cmd_id, UINT8 *iv_buf, UINT32 length);
#endif
#endif

extern unsigned int __npu_syscall_open_cmdproc(void);
extern unsigned int __npu_syscall_release_cmdproc(void *command_info);
extern unsigned int __npu_syscall_ioctl_cmdproc(void *command_info);

#endif
