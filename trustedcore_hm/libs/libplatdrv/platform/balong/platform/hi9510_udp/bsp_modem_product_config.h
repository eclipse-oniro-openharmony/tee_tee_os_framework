#ifndef __BSP_MODEM_PRODUCT_CONFIG_H
#define __BSP_MODEM_PRODUCT_CONFIG_H

#ifdef CONFIG_MODEM_SECBOOT_ES
#include <product_config_drv_ap_es.h>
#else
#include <product_config_drv_ap.h>
#endif
#endif