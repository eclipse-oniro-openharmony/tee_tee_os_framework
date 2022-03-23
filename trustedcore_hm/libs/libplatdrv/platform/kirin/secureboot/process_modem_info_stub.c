#include <sre_typedef.h>
#include <hisi_seclock.h>
#include <bsp_secboot_adp.h>
#include <osl_balong.h>

struct MODEM_LOAD g_modem_load;

UINT32 secboot_config_dynamic_load_addr(UINT32 soc_type)
{
    UNUSED(soc_type);
    return 0;
}

UINT32 hisi_secboot_is_modem_img(UINT32 SoC_Type)
{
    UNUSED(SoC_Type);
    return 0;
}

UINT32 hisi_secboot_verify_modem_imgs(UINT32 SoC_Type, UINT32 vrlAddress, UINT32 core_id, SECBOOT_LOCKSTATE lock_state)
{
    UNUSED(SoC_Type);
    UNUSED(vrlAddress);
    UNUSED(core_id);
    UNUSED(lock_state);
    return 0;
}

UINT32 hisi_modem_disreset(UINT32 soc_type)
{
    UNUSED(soc_type);
    return 0;
}
