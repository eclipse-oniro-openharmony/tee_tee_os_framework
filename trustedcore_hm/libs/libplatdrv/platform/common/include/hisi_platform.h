#ifndef __HISI_PLATFORM_H
#define __HISI_PLATFORM_H

#if defined (WITH_HIGENERIC_PLATFORM)

#if defined(WITH_CHIP_HI3650)
#include <platform_hi3650.h>
#elif defined(WITH_CHIP_HI3660)
#include <platform_hi3660.h>
#elif defined(WITH_CHIP_HI3670)
#include <platform_hi3670.h>
#elif defined(WITH_CHIP_HI6250)
#include <platform_hi6250.h>
#elif defined(WITH_CHIP_HI6260)
#include <platform_hi6260.h>
#elif defined(WITH_CHIP_HI3680)
#include <platform_hi3680.h>
#elif defined(WITH_CHIP_KIRIN990)

#if defined (WITH_KIRIN990_CS)
#include <platform_kirin990.h>
#else
#include <platform_kirin990_cs2.h>
#endif

#elif defined(WITH_CHIP_ORLANDO)
#include <platform_orlando.h> /*copy from hi3680.h*/
#elif defined(WITH_CHIP_MIAMICW)
#include <platform_hi6260.h>
#endif

#endif

#endif
