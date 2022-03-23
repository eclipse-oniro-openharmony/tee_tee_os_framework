#include <ese_config_hisi.h>

static unsigned int value[] = {
    0, // NXP_TP_MEASUREMENT
    0x05, // NXP_NAD_POLL_RETRY_TIME
    0x0200, // NXP_ESE_IFSD_VALUE
    0x0200, // NXP_EUICC_IFSD_VALUE
    0x01, // NXP_SOF_WRITE
    0x14, // NXP_SPI_WRITE_TIMEOUT
    0x00, // NXP_P61_COLD_RESET_INTERFACE
    30000, // NXP_WTX_COUNT_VALUE /* f00273901 30->30000 */
    7000, // RNACK_RETRY_DELAY
    0x03, // NXP_MAX_RNACK_RETRY
    0x01, // NXP_SPI_INTF_RST_ENABLE
    0x02, // NXP_POWER_SCHEME
    0x01, // NXP_VISO_DPD_ENABLED
    0x01, // NXP_P61_JCOP_DEFAULT_INTERFACE
};

bool EseConfig_hasKey(unsigned int KEY)
{
    (void)KEY;
    return true;
}

unsigned int EseConfig_getUnsigned(unsigned int KEY)
{
    return value[KEY];
}

const unsigned char * EseConfig_getString(unsigned int KEY, const unsigned char * defaultStr)
{
    (void)KEY;
    return defaultStr;
}