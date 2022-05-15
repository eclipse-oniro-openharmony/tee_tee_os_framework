#include <signal.h>
#include <string.h>
#include "libc.h"
#include "ksigaction.h"

int __sigaction(int sig, const struct sigaction *restrict sa, struct sigaction *restrict old)
{
    return 0;
}

weak_alias(__sigaction, sigaction);
