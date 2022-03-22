#ifndef _SECBOOT_H_
#define _SECBOOT_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECBOOT_VRL_SIZE (0x1000)

#define SECBOOT_RET_SUCCESS (0)
#define SECBOOT_RET_MODEM_IS_UNRESET (0xFFFFFF00)
#define SECBOOT_RET_INVALIED_SOC_TYPE (0xFFFFFF01)
#define SECBOOT_RET_INVALIED_PHY_ADDR (0xFFFFFF02)
#define SECBOOT_RET_INVALIED_OFFSET_OR_LEN (0xFFFFFF03)
#define SECBOOT_RET_SRC_MAP_FAILED (0xFFFFFF04)
#define SECBOOT_RET_DEPENDCORE_NOT_READY (0xFFFFFF05)
#define SECBOOT_RET_INVALIED_ZSTD_HEAD_INFO (0xFFFFFF06)
#define SECBOOT_RET_ASLR_RND_FAIL (0XFFFFFF24)
#define SECBOOT_RET_CERT_CHECK_FAIL (0XFFFFFF25)
#define SECBOOT_IMAGE_LEN_NOT_MATCH (0XFFFFFF26)
#define SECBOOT_RET_INVALIED_ST_ADDR (0XFFFFFF27)
#define SECBOOT_RET_FAIL_TO_GET_ST_INFO (0XFFFFFF28)
#define SECBOOT_RET_FAIL_TO_GET_VERIFY_INFO (0XFFFFFF29)
#define SECBOOT_RET_FAIL_TO_GET_MEM_LAYOUT (0XFFFFFF2A)

#define MODEM_REL_COPY_CODE_SIZE (64 * 1024)
#define MODEM_ASLR_4G_IDX 0
#define MODEM_ASLR_5G_IDX 1

/* the workspcae of ccs */
#define SECBOOT_DX_WORKSPACE_SIZE (6 * 1024)

extern unsigned long VRL_ADDR;
extern uint32_t SECBOOT_DX_WORKSPACE_ADDR[];

uint32_t hisi_secboot_verify_comm_imgs(int SoC_Type, uint32_t core_id);
struct SEC_BOOT_MODEM_INFO *modem_info_base_get(void);
uint32_t secboot_copy_vrl_data(void *dst_addr, const void *src_addr, uint32_t len);
uint32_t *hisi_secboot_get_vrl_buf(void);
uint32_t hisi_secboot_verify(unsigned long long vrl_addr_long, unsigned long long image_addr_long, unsigned image_size);
uint32_t hisi_secboot_set_mem_layout_info(int SoC_Type, uint32_t base_addr);

#ifdef __cplusplus
}
#endif

#endif
