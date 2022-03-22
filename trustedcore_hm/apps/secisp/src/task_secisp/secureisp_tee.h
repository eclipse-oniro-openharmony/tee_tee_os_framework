#ifndef __SECUREISP_H
#define __SECUREISP_H
#include <TEE_ext/sre_syscalls_id_ext.h>
#include <dynion.h> // TEE_PAGEINFO
#include "mem_mode.h" // TEE_PAGEINFO

/* syscall info */
#define ISP_SYSCALL_DISRESET          SW_SYSCALL_SECISP_DISRESET
#define ISP_SYSCALL_RESET             SW_SYSCALL_SECISP_RESET
#define ISP_SYSCALL_NONSEC_MEM_MAP    SW_SYSCALL_SECISP_NONSEC_MEM_MAP
#define ISP_SYSCALL_NONSEC_MEM_UNMAP  SW_SYSCALL_SECISP_NONSEC_MEM_UNMAP
#define ISP_SYSCALL_SEC_MEM_MAP       SW_SYSCALL_SECISP_SEC_MEM_MAP
#define ISP_SYSCALL_SEC_MEM_UNMAP     SW_SYSCALL_SECISP_SEC_MEM_UNMAP
#define ISP_SYSCALL_ISP_MEM_END       SW_SYSCALL_SECISP_MEM_END


/* ta info */
#define CameraDaemonSERVER_NAME     "/vendor/bin/CameraDaemon"
#define CameraDaemon_UID            (1013)
#define SECISP_DDR_SEC_FEATURE      (0x10)
#define SECISP_TASK_ID              (1)//SEC_TASK_SEC

/* static mem info */
#define STATIC_MEM_SGLIST_SIZE      (sizeof(struct sglist) + sizeof(TEE_PAGEINFO))
#define STATIC_MEM_INFOLENGTH       (1)
#define STATIC_MEM_PAGE_ALIGN       (0x1000)

/* mesage info */
#define SECISP_SEC                  0
#define SECISP_NSEC                 1

#define MAX_MALLOC_SIZE             (0x00080000) /* 512K */

typedef enum {
	SECISP_DDR_SET_SEC,
	SECISP_DDR_UNSET_SEC,
} SECISP_DDR_CFG_TYPE;

enum secisp_ta_tag {
	TEE_SECISP_CMD_IMG_DISRESET        = 0,
	TEE_SECISP_CMD_RESET               = 1,
	TEE_SECISP_SEC_MEM_CFG_AND_MAP     = 2,
	TEE_SECISP_SEC_MEM_CFG_AND_UNMAP   = 3,
	TEE_SECISP_NONSEC_MEM_MAP_SEC      = 4,
	TEE_SECISP_NONSEC_MEM_UNMAP_SEC    = 5,
	TEE_SECISP_BOOT_MEM_CFG_AND_MAP    = 6,
	TEE_SECISP_BOOT_MEM_CFG_AND_UNMAP  = 7,
	TEE_SECISP_CMD_MAX
};

enum secisp_mem_type {
	SECISP_TEXT = 0,
	SECISP_DATA,
	SECISP_SEC_POOL,
	SECISP_ISPSEC_POOL,
	SECISP_DYNAMIC_POOL,
	SECISP_RDR,
	SECISP_SHRD,
	SECISP_VQ,
	SECISP_VR0,
	SECISP_VR1,
	SECISP_MAX_TYPE
};

enum hisp_sec_boot_mem_type {
	HISP_SEC_TEXT       = 0,
	HISP_SEC_DATA       = 1,
	HISP_SEC_BOOT_MAX_TYPE
};

enum hisp_sec_rsv_mem_type {
	HISP_SEC_VR0       = 0,
	HISP_SEC_VR1       = 1,
	HISP_SEC_VQ        = 2,
	HISP_SEC_SHARE     = 3,
	HISP_SEC_RDR       = 4,
	HISP_SEC_RSV_MAX_TYPE
};

typedef struct isp_ion_mem_type {
	unsigned int type;
	unsigned int da;
	unsigned int size;
	unsigned int prot;
	unsigned int sec_flag;/* SEC or NESC*/
	int sharefd;
	unsigned long long pa;
} TEE_ISP_MEM_INFO;

struct secisp_img_mem_info {
	TEE_ISP_MEM_INFO info;
	unsigned int sfd;
};

struct secisp_boot_mem_info {
	TEE_ISP_MEM_INFO rsv_info[HISP_SEC_RSV_MAX_TYPE];
	struct secisp_img_mem_info img_info[HISP_SEC_BOOT_MAX_TYPE];
};

#define ISP_DEBUG_ENABLE               (1 << 0)
#define ISP_WARRING_ENABLE             (1 << 1)
#define ISP_INFO_MASK                  (1 << 2)
#define ISP_ERR_MASK                   (1 << 3)

extern void uart_printf_func(const char *fmt, ...);

#define ISP_PRINT_FLAG \
		(ISP_ERR_MASK | ISP_WARRING_ENABLE | ISP_INFO_MASK)

#define isp_err(fmt, args...) \
	do { \
		if (ISP_PRINT_FLAG & ISP_ERR_MASK) { \
			uart_printf_func("[secisp][E]<%s,%d> " fmt, __func__, __LINE__, ##args); \
		} \
	} while(0)

#define isp_warn(fmt, args...) \
	do { \
		if (ISP_PRINT_FLAG & ISP_WARRING_ENABLE) {	\
			uart_printf_func("[secisp][W]<%s,%d> " fmt, __func__, __LINE__, ##args); \
		} \
	} while(0)

#define isp_info(fmt, args...) \
	do { \
		if (ISP_PRINT_FLAG & ISP_INFO_MASK) {	\
			uart_printf_func("[secisp][I]<%s,%d> " fmt, __func__, __LINE__, ##args); \
		} \
	} while(0)

#define isp_debug(fmt, args...) \
	do { \
		if (ISP_PRINT_FLAG & ISP_DEBUG_ENABLE) { \
			uart_printf_func("[secisp][D]<%s,%d> " fmt, __func__, __LINE__, ##args); \
		} \
	} while(0)


#endif
