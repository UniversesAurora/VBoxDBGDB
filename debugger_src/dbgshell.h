// Copyright 2021 浮枕
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SDK_BINDINGS_C_SERVER_DBGSHELL
#define SDK_BINDINGS_C_SERVER_DBGSHELL

#include <errno.h>
#include <stdarg.h>
#include <semaphore.h>

#include "dbgapi.h"
#include "dbgshellcmd.h"
#include "dbggdbserver.h"


typedef struct cmd_item
{
    char* cmd_name;
    DBGRET (*cmd_handler)(unsigned long, char**);
    char* cmd_syntax;
    char* cmd_description;
} cmd_item;

typedef struct dbgret_item
{
    char* dbgret_name;
    char* dbgret_msg_level;
    char* dbgret_msg;
} dbgret_item;


extern const cmd_item dbgshell_cmds[];
extern const uint64_t dbgshell_cmds_sz;

extern sem_t global_lock;

extern IVirtualBoxClient* g_vboxclient;
extern IVirtualBox* g_vbox;
extern ISession* g_session;
extern IMachine* g_machine;
extern IProgress* g_progress;
extern IConsole* g_console;
extern IMachineDebugger* g_debugger;
extern uint32_t g_cpuid;
extern uint8_t g_shell_ready;
extern uint8_t g_shell_wait_input;

void PrintErrorInfo(const char *pszExecutable, const char *pszErrorMsg, HRESULT rc);
void _print_error(const char *exec_name, const char *error_msg, HRESULT rc);
void _print_sys_error(const char *filename, const char *type, const char *loc_func, const char *src_func);
void _print_message(const char *filename, const char *type, const char *src, const char *fmt, ...);
void dbgshell_print_message_dbgret(const char *src_func, DBGRET ret);
void clean_stdin();
int8_t stdin_is_eof();
void dbgshell_draw_prompt();
DBGRET dbgshell_start(IProgress *progress, IMachine *machine, ISession *session, IVirtualBox *vbox, IVirtualBoxClient *vbox_client);

#define DBGSHELL_MSGINFO "INFO"
#define DBGSHELL_MSGWARN "WARNING"
#define DBGSHELL_MSGERRO "ERROR"

#define print_error(loc_func, src_func, rc) \
_print_error(FLNM ":" loc_func "()", src_func "()", rc)

#define print_sys_error(type, loc_func, src_func) \
_print_sys_error(FLNM, type, loc_func, src_func)

#define print_message(type, src, ...) \
_print_message(FLNM, type, src, __VA_ARGS__)

#define print_normal(...) \
{ \
printf(__VA_ARGS__); \
dbgshell_draw_prompt(); \
}

#endif /* SDK_BINDINGS_C_SERVER_DBGSHELL */
