#define _GNU_SOURCE

#include <signal.h>
#include <string.h>

#include "sigutils.h"
#include "trace.h"

int ignore_signal(int signal)
{
        int rc = -1;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        if (sigaction(signal, &sa, NULL) == -1) {
                TRACE_ERRNO("sigaction(SIGHUP) failed");
                goto _out;
        }
        rc = 0;
_out:
        return rc;
}

