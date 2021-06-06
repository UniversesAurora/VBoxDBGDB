#ifndef SDK_BINDINGS_C_SERVER_DBGSHELLCMD
#define SDK_BINDINGS_C_SERVER_DBGSHELLCMD

#include <string.h>
#include <pthread.h>

#include "dbgapi.h"
#include "dbgshell.h"

DBGRET dbgshellcmd_exit(unsigned long argc, char **argv);
DBGRET dbgshellcmd_help(unsigned long argc, char **argv);
DBGRET dbgshellcmd_cpu(unsigned long argc, char **argv);
DBGRET dbgshellcmd_rg(unsigned long argc, char **argv);
DBGRET dbgshellcmd_cvp(unsigned long argc, char **argv);
DBGRET dbgshellcmd_dmp(unsigned long argc, char **argv);
DBGRET dbgshellcmd_dmv(unsigned long argc, char **argv);
DBGRET dbgshellcmd_empb(unsigned long argc, char **argv);
DBGRET dbgshellcmd_empw(unsigned long argc, char **argv);
DBGRET dbgshellcmd_empd(unsigned long argc, char **argv);
DBGRET dbgshellcmd_empq(unsigned long argc, char **argv);
DBGRET dbgshellcmd_emvb(unsigned long argc, char **argv);
DBGRET dbgshellcmd_emvw(unsigned long argc, char **argv);
DBGRET dbgshellcmd_emvd(unsigned long argc, char **argv);
DBGRET dbgshellcmd_emvq(unsigned long argc, char **argv);
DBGRET dbgshellcmd_g(unsigned long argc, char **argv);
DBGRET dbgshellcmd_stop(unsigned long argc, char **argv);
DBGRET dbgshellcmd_so(unsigned long argc, char** argv);
DBGRET dbgshellcmd_si(unsigned long argc, char** argv);
DBGRET dbgshellcmd_ba(unsigned long argc, char** argv);
DBGRET dbgshellcmd_bc(unsigned long argc, char** argv);
DBGRET dbgshellcmd_bl(unsigned long argc, char** argv);
DBGRET dbgshellcmd_gdbopen(unsigned long argc, char **argv);
DBGRET dbgshellcmd_gdbclose(unsigned long argc, char **argv);

#endif /* SDK_BINDINGS_C_SERVER_DBGSHELLCMD */
