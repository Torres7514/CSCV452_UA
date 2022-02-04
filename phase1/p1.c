#include "usloss.h"
#define DEBUG 0
extern int debugflag;

void
p1_fork(int pid)
{
    if (DEBUG && debugflag)
      console("p1_fork() called: PID = %d\n", pid);
}

void
p1_switch(int old, int new)
{
    if (DEBUG && debugflag)
      console("p1_switch() called: OLD = %d, NEW = %d\n", old, new);
}

void
p1_quit(int pid)
{
    if (DEBUG && debugflag)
      console("p1_quit() called: PID = %d\n", pid);
}

int check_io()
{
    return 0;
}