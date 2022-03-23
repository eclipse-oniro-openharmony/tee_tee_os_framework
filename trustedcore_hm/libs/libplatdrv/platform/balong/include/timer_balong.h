#ifndef __TIMER_AUSTIN_H__
#define __TIMER_AUSTIN_H__

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6965)
#define TIMER8_BASE     0xedf1f000   //timer60 for secure os(Do not power off)
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6932)
#define TIMER8_BASE     0x2001F000   //timer60 for secure os(Do not power off)
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI9500)
#define TIMER8_BASE     0xedf1f000   //timer60 for secure os(Do not power off)
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI9510)
#define TIMER8_BASE     0xedf19000   //timer60 for secure os(Do not power off)
#endif

#define FREE_RUNNING_TIMER_BASE     TIMER8_BASE
#define TICK_TIMER_BASE             TIMER8_BASE

#define FREE_RUNNING_TIMER_NUM    (1)
#define TICK_TIMER_NUM (0)

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI9500)
//timer8  1
#define FREE_RUNNING_FIQ_NUMBLER     74
//timer8  0
#define TICK_TIMER_FIQ_NUMBLER       73
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI9510)
#define FREE_RUNNING_FIQ_NUMBLER     81
#define TICK_TIMER_FIQ_NUMBLER       82
#endif


/*NMI watchdog*/
#define WDT_FIQ_NUMBLER    84
//Secure RTC1
//NMI watchdog
#define SGI_DUMP_NUMBLER   0xB

//SPI number to call normal world tc_notify_func
#define SPI_NUM_FOR_NOTIFY (72)

/*For K3V3 FPGA*/
#define TIMER_SECU_EN          (1<<16)

/*Timer01??¨¦Timer23??¨¦Timer45??¨¦Timer67¡§o1?¡§1??????¡§¡è-??|¨¬?¡§?2?t¡§o1?¡§1??????¨º*/
#define TIME_FORCE_HIGH        (1<<8)

#define SCCTRL_TIMEREN0SEL_TIMCLK   (1 << 9)
#define SCCTRL_TIMEREN1SEL_TIMCLK   (1 << 11)
#define SCCTRL_TIMEREN2SEL_TIMCLK   (1 << 13)
#define SCCTRL_TIMEREN3SEL_TIMCLK   (1 << 15)
#define SCCTRL_TIMEREN4SEL_TIMCLK   (1 << 17)
#define SCCTRL_TIMEREN5SEL_TIMCLK   (1 << 19)
#define SCCTRL_TIMEREN6SEL_TIMCLK   (1 << 21)
#define SCCTRL_TIMEREN7SEL_TIMCLK   (1 << 23)
#define PTCRL_TIMEEREN8SEL_TIMCLK   (1 << 0)
#define PTCRL_TIMEEREN9SEL_TIMCLK   (1 << 2)
#define PTCRL_TIMEEREN10SEL_TIMCLK   (1 << 4)
#define PTCRL_TIMEEREN11SEL_TIMCLK   (1 << 6)
#define PTCRL_TIMEEREN12SEL_TIMCLK   (1 << 8)
#define PTCRL_TIMEEREN13SEL_TIMCLK   (1 << 10)
#define PTCRL_TIMEEREN14SEL_TIMCLK   (1 << 12)
#define PTCRL_TIMEEREN15SEL_TIMCLK   (1 << 14)


#define TIMER_LOAD      0x00
#define TIMER_VALUE     0x04
#define TIMER_CTRL      0x08
#define TIMER_CTRL_ONESHOT  (1 << 0)
#define TIMER_CTRL_32BIT    (1 << 1)
#define TIMER_CTRL_DIV1     (0 << 2)
#define TIMER_CTRL_DIV16    (1 << 2)
#define TIMER_CTRL_DIV256   (2 << 2)
#define TIMER_CTRL_IE       (1 << 5)    /* Interrupt Enable (versatile only) */
#define TIMER_CTRL_PERIODIC (1 << 6)
#define TIMER_CTRL_ENABLE   (1 << 7)

#define TIMER_GT_CLK_TIMER1  (1 << 6)
#define TIMER_GT_PCLK_TIMER1 (1 << 5)
#define TIMER_GT_PCLK_TIMER6 (1 << 24)


#define TIMER_INTCLR        0x0c
#define TIMER_RIS       0x10
#define TIMER_MIS       0x14
#define TIMER_BGLOAD        0x18

#endif /* __TIMER_PLAT_H__ */

