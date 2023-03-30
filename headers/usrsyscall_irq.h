#ifndef USRSYSCALL_IRQ_H
#define USRSYSCALL_IRQ_H

#include <stdint.h>

int32_t enable_local_irq(void);

int32_t disable_local_irq(void);

void init_sysctrl_hdlr(void);

#endif