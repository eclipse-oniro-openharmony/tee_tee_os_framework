#include <osl_balong.h>
#include <mem_page_ops.h>
#include <drv_module.h>
#include <hm_mman_ext.h>
#include <tee_log.h> /* uart_printf_func */
#include <bsp_modem_call.h>
#include <securec.h>
#include <secboot.h>

#define sec_dump_print(fmt,...)  uart_printf_func("[sec_dump]:"fmt, ##__VA_ARGS__)
/*每个平台均需要适配基地址及偏移，下一步将偏移适配移植到fastboot dts中完成*/
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#define SOCP_BASE_ADDR                      (0xff060000)
#define SOCP_CODER_SRC_READ_OFFSET(channel)          (0x100+0x40*(channel))
#define SOCP_CODER_SRC_WRITE_OFFSET(channel)         (0x104+0x40*(channel))
#define SOCP_CODER_SRC_CFG_OFFSET(channel)           (0x114+0x40*(channel))
#define SOCP_CODER_DST_CFG_OFFSET(channel)           (0x91c+0x20*(channel))
#define SOCP_SEC_DUMP_LR_SRC_CHANNEL                 (30)
#define SOCP_SEC_DUMP_NR_SRC_CHANNEL                 (30)
#define SOCP_SEC_DUMP_DST_CHANNEL                    (2)

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#define SOCP_BASE_ADDR                      (0xfa0a0000)

#ifdef MODEM_SOCP_3_0
#define SOCP_CODER_SRC_READ_OFFSET(channel)          (0x300+0x40*(channel))
#define SOCP_CODER_SRC_WRITE_OFFSET(channel)         (0x304+0x40*(channel))
#define SOCP_CODER_SRC_CFG_OFFSET(channel)           (0x314+0x40*(channel))
#define SOCP_CODER_DST_CFG_OFFSET(channel)           (0x131c+0x40*(channel))
#define SOCP_SEC_DUMP_LR_SRC_CHANNEL                 (50)
#define SOCP_SEC_DUMP_NR_SRC_CHANNEL                 (51)
#else
#define SOCP_CODER_SRC_READ_OFFSET(channel)          (0x100+0x40*(channel))
#define SOCP_CODER_SRC_WRITE_OFFSET(channel)         (0x104+0x40*(channel))
#define SOCP_CODER_SRC_CFG_OFFSET(channel)           (0x114+0x40*(channel))
#define SOCP_CODER_DST_CFG_OFFSET(channel)           (0x91c+0x20*(channel))
#define SOCP_SEC_DUMP_LR_SRC_CHANNEL                 (30)
#define SOCP_SEC_DUMP_NR_SRC_CHANNEL                 (30)
#endif
#define SOCP_SEC_DUMP_DST_CHANNEL                    (2)
#else
#define SOCP_BASE_ADDR                      (0)
#define SOCP_CODER_SRC_READ_OFFSET(channel)          (0)
#define SOCP_CODER_SRC_WRITE_OFFSET(channel)         (0)
#define SOCP_CODER_SRC_CFG_OFFSET(channel)           (0)
#define SOCP_CODER_DST_CFG_OFFSET(channel)           (0)
#define SOCP_SEC_DUMP_LR_SRC_CHANNEL        (30)
#define SOCP_SEC_DUMP_NR_SRC_CHANNEL        (30)
#define SOCP_SEC_DUMP_DST_CHANNEL           (2)
#endif

#define MODEM_SEC_DUMP_ENABLE_LR_CHANNEL_CMD       (0x56781234)
#define MODEM_SEC_DUMP_ENABLE_NR_CHANNEL_CMD       (0x78563412)
#define MODEM_SEC_DUMP_STOP_LR_CHANNEL_CMD         (0x12345678)
#define MODEM_SEC_DUMP_STOP_NR_CHANNEL_CMD         (0x34127856)

// do map in hm_io_mmap when platdrv init
volatile void* g_socp_addr = (volatile void*)SOCP_BASE_ADDR;

void socp_src_channel_enable(u32 channel_id)
{
    volatile unsigned int src_cfg=0;
    unsigned int rp = 0;
    unsigned int wp = 0;
    if(!g_socp_addr)
        return;

    rp = readl((u32)g_socp_addr + SOCP_CODER_SRC_READ_OFFSET(channel_id));
    wp = readl((u32)g_socp_addr + SOCP_CODER_SRC_WRITE_OFFSET(channel_id));

    /*如果读写指针完全一致，则直接退出即可*/
    if(rp == wp)
        return ;

    src_cfg = readl((u32)g_socp_addr + SOCP_CODER_SRC_CFG_OFFSET(channel_id));
    if(src_cfg&0x1)
        return;
    src_cfg |= 0x1;
    writel(src_cfg,(u32)g_socp_addr + SOCP_CODER_SRC_CFG_OFFSET(channel_id));

    sec_dump_print("%s 0x%x src_cfg=0x%x\n",__func__,g_socp_addr,src_cfg);
    return ;
}

void socp_src_channel_disable(u32 channel_id)
{
    volatile unsigned int src_cfg=0;

    if(!g_socp_addr)
        return;

    src_cfg = readl((u32)g_socp_addr + SOCP_CODER_SRC_CFG_OFFSET(channel_id));
    if(src_cfg&0x1){
        src_cfg =src_cfg & (~1);
        writel(src_cfg,(u32)g_socp_addr + SOCP_CODER_SRC_CFG_OFFSET(channel_id));
    }
    writel(0,(u32)g_socp_addr + SOCP_CODER_SRC_READ_OFFSET(channel_id));
    writel(0,(u32)g_socp_addr + SOCP_CODER_SRC_WRITE_OFFSET(channel_id));
    sec_dump_print("%s 0x%x\n",__func__,g_socp_addr);
    return ;
}
int bsp_sec_dump_channel_enable(unsigned int arg1, void *arg2, unsigned int arg3)
{
    void *ptr = NULL;
    unsigned int tmp;
    ptr = arg2;
    arg2 = ptr;
    tmp = arg3;
    arg3 = tmp;

    switch(arg1)
    {
        case MODEM_SEC_DUMP_ENABLE_LR_CHANNEL_CMD:
            /*enable src channel*/
            socp_src_channel_enable(SOCP_SEC_DUMP_LR_SRC_CHANNEL);
            sec_dump_print("enable lr sec dump\n");
            break;
        case MODEM_SEC_DUMP_ENABLE_NR_CHANNEL_CMD:
            /*enable src channel*/
            socp_src_channel_enable(SOCP_SEC_DUMP_NR_SRC_CHANNEL);
            sec_dump_print("enable nr sec dump\n");
            break;
        case MODEM_SEC_DUMP_STOP_LR_CHANNEL_CMD:
            /*enable src channel*/
            socp_src_channel_disable(SOCP_SEC_DUMP_LR_SRC_CHANNEL);
            sec_dump_print("disable lr sec dump\n");
            break;
        case MODEM_SEC_DUMP_STOP_NR_CHANNEL_CMD:
            /*enable src channel*/
            socp_src_channel_disable(SOCP_SEC_DUMP_NR_SRC_CHANNEL);
            sec_dump_print("disable nr sec dump\n");
            break;
        default:
            /*disable src channel*/
            socp_src_channel_disable(SOCP_SEC_DUMP_LR_SRC_CHANNEL);
#ifdef MODEM_SOCP_3_0
            socp_src_channel_disable(SOCP_SEC_DUMP_NR_SRC_CHANNEL);
#endif
            break;
    }


    return 0;
}

int bsp_sec_dump_init(void)
{
    if(SOCP_BASE_ADDR)
    {
        //注册sec_call回调
        (void)bsp_modem_call_register(FUNC_SEC_DUMP_CHANNEL_ENABLE,(MODEM_CALL_HOOK_FUNC)bsp_sec_dump_channel_enable);
    }
    sec_dump_print("init 0x%x\n",g_socp_addr);
    return 0;
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_BALTIMORE && TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER && \
	TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_MIAMICW)
/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(
    sec_dump,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    bsp_sec_dump_init,
    NULL,
    NULL,
    NULL,
    NULL
);
/*lint -e528 +esym(528,*)*/
#endif
