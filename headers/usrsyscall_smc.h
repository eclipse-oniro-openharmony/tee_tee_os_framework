#ifndef USRSYSCALL_SMC_H
#define USRSYSCALL_SMC_H

#include <stddef.h>
#include <stdint.h>

struct cap_teesmc_buf {
	uint64_t ops;
	uint64_t ta;
	uint64_t target;
};

enum cap_teesmc_buf_ops {
    CAP_TEESMC_OPS_NORMAL = 0,
};

enum cap_teesmc_req {
    CAP_TEESMC_REQ_STARTTZ,
    CAP_TEESMC_REQ_IDLE,
};

int32_t smc_wait_switch_req(struct cap_teesmc_buf *buf);

int32_t smc_switch_req(enum cap_teesmc_req switch_req);

void init_teesmc_hdlr(void);

#endif
