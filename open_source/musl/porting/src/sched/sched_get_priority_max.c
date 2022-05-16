#include <uapi/priorities_kernel.h>

int sched_get_priority_max(int policy __attribute__((unused)))
{
	// take care about policy later
	return HM_PRIO_KERNEL_CAN_CONFIG_MAX;
}

int sched_get_priority_min(int policy __attribute__((unused)))
{
	// take care about policy later
	return HM_PRIO_KERNEL_CAN_CONFIG_MIN;
}
