#ifndef __HWSPINLOCK_H
#define __HWSPINLOCK_H

#define HS_OK 0
#define HS_EFAIL (-1)
#define HS_EID (-2)
#define HS_EPARAM (-3)
#define HS_ETMOUT (-4)

#define WAITTIME_MAX 500000
#define WAITFVR 0xffffffff

int hwspin_unlock(int id);
int hwspin_lock_timeout(int id, unsigned int to);
#endif
