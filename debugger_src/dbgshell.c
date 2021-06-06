/**
 * Copyright 2021 浮枕
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "dbgshell.h"


#define FLNM "dbgshell.c"
#define ONE_ALLOC_NUM 16


const cmd_item dbgshell_cmds[] =
{
    {"exit", dbgshellcmd_exit, "", "Exit debug shell"},
    {"help", dbgshellcmd_help, "[command]", "Display help"},
    {"cpu", dbgshellcmd_cpu, "[new cpuid]", "Display current CPU or switch to new CPU"},
    {"rg", dbgshellcmd_rg, "[reg [new value]]", "Show or set register(s)"},
    {"cvp", dbgshellcmd_cvp, "[address]", "Convert virtual address to physical address"},
    {"dmp", dbgshellcmd_dmp, "[address [line count]]", "Dump physical memory"},
    {"dmv", dbgshellcmd_dmv, "[address [line count]]", "Dump virtual memory"},
    {"empb", dbgshellcmd_empb, "[address] [value]", "Write 1-byte value to physical memory"},
    {"empw", dbgshellcmd_empw, "[address] [value]", "Write 2-byte value to physical memory"},
    {"empd", dbgshellcmd_empd, "[address] [value]", "Write 4-byte value to physical memory"},
    {"empq", dbgshellcmd_empq, "[address] [value]", "Write 8-byte value to physical memory"},
    {"emvb", dbgshellcmd_emvb, "[address] [value]", "Write 1-byte value to virtual memory"},
    {"emvw", dbgshellcmd_emvw, "[address] [value]", "Write 2-byte value to virtual memory"},
    {"emvd", dbgshellcmd_emvd, "[address] [value]", "Write 4-byte value to virtual memory"},
    {"emvq", dbgshellcmd_emvq, "[address] [value]", "Write 8-byte value to virtual memory"},
    {"g", dbgshellcmd_g, "", "Continue execution"},
    {"stop", dbgshellcmd_stop, "", "Stop execution"},
    {"so", dbgshellcmd_so, "", "Step over"},
    {"si", dbgshellcmd_si, "", "Step into"},
    {"ba", dbgshellcmd_ba, "[is_hard_brkp] [hard_type] [address] [hit_trigger] [has_hit_disable] [hit_disable] [access_sz]", "Add breakpoint"},
    {"bc", dbgshellcmd_bc, "[ibp]", "Delete breakpoint"},
    {"bl", dbgshellcmd_bl, "", "List breakpoints"},
    {"gdbopen", dbgshellcmd_gdbopen, "[port]", "Open GDB remote server"},
    {"gdbclose", dbgshellcmd_gdbclose, "", "Close GDB remote server"},
};
const uint64_t dbgshell_cmds_sz = RT_ELEMENTS(dbgshell_cmds);

const dbgret_item dbgshell_dbgret_items[] =
{
    {"DBGRET_SUCCESS", DBGSHELL_MSGINFO, "Success"},
    {"DBGRET_EINIT", DBGSHELL_MSGERRO, "Error initializing dbgapi"},
    {"DBGRET_ERELEASE", DBGSHELL_MSGERRO, "Error Releasing dbgapi"},
    {"DBGRET_EGENERAL", DBGSHELL_MSGERRO, "General error occurred"},
    {"DBGRET_ESHELL", DBGSHELL_MSGERRO, "Unknown shell error"},
    {"DBGRET_EOUTOFMEM", DBGSHELL_MSGERRO, "Out of memory"},
    {"DBGRET_EMPTYLINE", DBGSHELL_MSGINFO, "Empty line received"},
    {"DBGRET_TERMINATE", DBGSHELL_MSGINFO, "Terminating shell"},
    {"DBGRET_EPARSE", DBGSHELL_MSGERRO, "Error parsing arguments"},
    {"DBGRET_ECMDFAIL", DBGSHELL_MSGERRO, "Error executing command"},
    {"DBGRET_EARGTOOFEW", DBGSHELL_MSGERRO, "Too few arguments"},
    {"DBGRET_EARGTOOMANY", DBGSHELL_MSGERRO, "Too many arguments"},
    {"DBGRET_ENULLPTR", DBGSHELL_MSGERRO, "Trying to reference a NULL pointer"},
};
const uint64_t dbgshell_dbgret_items_sz = RT_ELEMENTS(dbgshell_dbgret_items);

/**
 *  Global variables
 */
sem_t global_lock;

IVirtualBoxClient* g_vboxclient = NULL;
IVirtualBox* g_vbox = NULL;
ISession* g_session = NULL;
IMachine* g_machine = NULL;
IProgress* g_progress = NULL;
IConsole* g_console = NULL;
IMachineDebugger* g_debugger = NULL;
uint32_t g_cpuid = 0;
uint8_t g_shell_ready = 0;
uint8_t g_shell_wait_input = 0;

/**
 * Print detailed error information if available.
 * @param   pszExecutable   string with the executable name
 * @param   pszErrorMsg     string containing the code location specific error message
 * @param   rc              COM/XPCOM result code
 */
void PrintErrorInfo(const char *pszExecutable, const char *pszErrorMsg, HRESULT rc)
{
    IErrorInfo *ex;
    HRESULT rc2;
    fprintf(stderr, "%s: %s (rc=%#010x)\n", pszExecutable, pszErrorMsg, (unsigned)rc);
    rc2 = g_pVBoxFuncs->pfnGetException(&ex);
    if (SUCCEEDED(rc2) && ex)
    {
        IVirtualBoxErrorInfo *ei;
        rc2 = IErrorInfo_QueryInterface(ex, &IID_IVirtualBoxErrorInfo, (void **)&ei);
        if (SUCCEEDED(rc2) && ei != NULL)
        {
            /* got extended error info, maybe multiple infos */
            do
            {
                LONG resultCode = S_OK;
                BSTR componentUtf16 = NULL;
                char *component = NULL;
                BSTR textUtf16 = NULL;
                char *text = NULL;
                IVirtualBoxErrorInfo *ei_next = NULL;
                fprintf(stderr, "Extended error info (IVirtualBoxErrorInfo):\n");

                IVirtualBoxErrorInfo_get_ResultCode(ei, &resultCode);
                fprintf(stderr, "  resultCode=%#010x\n", (unsigned)resultCode);

                IVirtualBoxErrorInfo_get_Component(ei, &componentUtf16);
                g_pVBoxFuncs->pfnUtf16ToUtf8(componentUtf16, &component);
                g_pVBoxFuncs->pfnComUnallocString(componentUtf16);
                fprintf(stderr, "  component=%s\n", component);
                g_pVBoxFuncs->pfnUtf8Free(component);

                IVirtualBoxErrorInfo_get_Text(ei, &textUtf16);
                g_pVBoxFuncs->pfnUtf16ToUtf8(textUtf16, &text);
                g_pVBoxFuncs->pfnComUnallocString(textUtf16);
                fprintf(stderr, "  text=%s\n", text);
                g_pVBoxFuncs->pfnUtf8Free(text);

                rc2 = IVirtualBoxErrorInfo_get_Next(ei, &ei_next);
                if (FAILED(rc2))
                    ei_next = NULL;
                IVirtualBoxErrorInfo_Release(ei);
                ei = ei_next;
            } while (ei);
        }

        IErrorInfo_Release(ex);
        g_pVBoxFuncs->pfnClearException();
    }
}

void _print_error(const char *exec_name, const char *error_msg, HRESULT rc)
{
    PrintErrorInfo(exec_name, error_msg, rc);
    dbgshell_draw_prompt();
}

void _print_sys_error(const char* filename, const char* type, const char* loc_func, const char* src_func)
{
    fprintf(stderr, "[%s] System error occurred when executing %s() (at %s()@%s) : %s\n",
                        type, src_func, loc_func, filename, strerror(errno));
    dbgshell_draw_prompt();
}

void _print_message(const char* filename, const char* type, const char* src, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    printf("[%s] %s()@%s : ", type, src, filename);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
    dbgshell_draw_prompt();
}

void dbgshell_print_message_dbgret(const char* src_func, DBGRET ret)
{
    if (ret >= dbgshell_dbgret_items_sz)
    {
        print_message(DBGSHELL_MSGERRO, src_func, "DBGRET out of range");
        return;
    }

    print_message(dbgshell_dbgret_items[ret].dbgret_msg_level, src_func, "%s: %s", dbgshell_dbgret_items[ret].dbgret_name, dbgshell_dbgret_items[ret].dbgret_msg);
}

void clean_stdin()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int8_t stdin_is_eof()
{
    return getchar() == EOF;
}


void dbgshell_draw_prompt()
{
    if (g_shell_wait_input)
        printf("cpu#%u dbg> ", g_cpuid);
    fflush(stdout);
}

char* dbgshell_to_next_arg(char* input)
{
    while(*input == ' ' || *input == '\t') input++;
    return input;
}

int dbgshell_char_is_legal(char c)
{
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || c == '+' || c == '-' || c == '.' || c == '_')
        return 1;

    return 0;
}

char* dbgshell_to_arg_end(char* input)
{
    while(dbgshell_char_is_legal(*input)) input++;
    return input;
}


DBGRET dbgshell_process_args(unsigned long* argc, char*** argv, char* input, ssize_t input_len)
{
    char *walk = dbgshell_to_next_arg(input);
    if (input_len <= 0 || *walk == '\n' || *walk == '\0')
    {
        return DBGRET_EMPTYLINE;
    }

    if (*argv)
    {
        free(*argv);
        *argv = NULL;
    }
    *argc = 0;

    while (walk - input < input_len && *walk != '\n' && *walk != '\0')
    {
        if (*argc % ONE_ALLOC_NUM == 0)
        {
            if (!(*argv = realloc(*argv, sizeof(char*)*(*argc+ONE_ALLOC_NUM))))
            {
                free(*argv);
                *argv = NULL;
                return DBGRET_EOUTOFMEM;
            }
        }

        walk = dbgshell_to_next_arg(walk);
        char* next = dbgshell_to_arg_end(walk);
        *next = '\0';
        (*argv)[*argc] = walk;

        (*argc)++;
        walk = next+1;
    }

    return DBGRET_SUCCESS;
}

DBGRET dbgshell_exec_cmd(unsigned long argc, char** argv)
{
    DBGRET drc;
    uint64_t i;

    if (argv[0][0] == '\0')
    {
        sem_wait(&global_lock);
        print_message(DBGSHELL_MSGWARN, "dbgshell_exec_cmd", "Illegal command name");
        sem_post(&global_lock);
        drc = DBGRET_SUCCESS;
        goto END;
    }

    for (i = 0; i < dbgshell_cmds_sz; i++)
    {
        if (strcmp(argv[0], dbgshell_cmds[i].cmd_name) == 0)
        {
            sem_wait(&global_lock);
            drc = dbgshell_cmds[i].cmd_handler(argc, argv);
            sem_post(&global_lock);
            break;
        }
    }

    if (i == dbgshell_cmds_sz)
    {
        sem_wait(&global_lock);
        print_message(DBGSHELL_MSGWARN, "dbgshell_exec_cmd", "Command %s not found", argv[0]);
        sem_post(&global_lock);
        drc = DBGRET_SUCCESS;
    }

END:
    return drc;
}


DBGRET dbgshell_run()
{
    DBGRET drc = DBGRET_SUCCESS;
    char *input = NULL;
    size_t input_bufsize = 0;
    ssize_t input_len;

    char** argv = NULL;
    unsigned long argc = 0;

    while(1)
    {
        sem_wait(&global_lock);
        drc = wait4event_dbgapi(g_debugger);
        sem_post(&global_lock);
        if (drc)
        {
            sem_wait(&global_lock);
            print_message(DBGSHELL_MSGWARN, "dbgshell_run", "Wait event failed");
            dbgshell_print_message_dbgret("dbgshell_run", drc);
            sem_post(&global_lock);
            drc = DBGRET_SUCCESS;
        }

        sem_wait(&global_lock);
        g_shell_wait_input = 1;
        sem_post(&global_lock);
        dbgshell_draw_prompt();
        input_len = getline(&input, &input_bufsize, stdin);
        sem_wait(&global_lock);
        drc = wait4event_dbgapi(g_debugger);
        g_shell_wait_input = 0;
        sem_post(&global_lock);
        if (drc)
        {
            sem_wait(&global_lock);
            print_message(DBGSHELL_MSGWARN, "dbgshell_run", "Wait event failed");
            dbgshell_print_message_dbgret("dbgshell_run", drc);
            sem_post(&global_lock);
            drc = DBGRET_SUCCESS;
        }

        if (input_len > 0)
        {
            debug_printf("Get input: %s", input);

            drc = dbgshell_process_args(&argc, &argv, input, input_len);
            if (drc)
            {
                printf("\n");
                if (drc == DBGRET_EOUTOFMEM)
                {
                    sem_wait(&global_lock);
                    print_message(DBGSHELL_MSGERRO, "dbgshell_run", "Out of memory");
                    sem_post(&global_lock);
                }
                continue;
            }

            debug_print_tag();
            for (int i = 0; i < argc; i++)
            {
                debug_printf_normal("(%s)\t", argv[i]);
            }
            debug_printf_normal("\n");

            drc = dbgshell_exec_cmd(argc, argv);

            if (drc == DBGRET_TERMINATE)
            {
                sem_wait(&global_lock);
                print_message(DBGSHELL_MSGINFO, "dbgshell_run", "Exiting...");
                sem_post(&global_lock);
                break;
            }
            else if (drc)
            {
                sem_wait(&global_lock);
                dbgshell_print_message_dbgret("dbgshell_run", drc);
                sem_post(&global_lock);
            }
        }
        else if (input_len == 0)
        {
            clean_stdin();
            continue;
        }
        else
        {
            if (stdin_is_eof())
            {
                printf("exit\n");

                sem_wait(&global_lock);
                drc = dbgshellcmd_exit(0, NULL);
                if (drc != DBGRET_TERMINATE)
                {
                    dbgshell_print_message_dbgret("dbgshell_run", drc);
                }

                print_message(DBGSHELL_MSGINFO, "dbgshell_run", "Exiting...");
                sem_post(&global_lock);
                break;
            }
            else
            {
                sem_wait(&global_lock);
                print_sys_error(DBGSHELL_MSGERRO, "dbgshell_run", "getline");
                sem_post(&global_lock);
                clean_stdin();
                continue;
            }
        }
    }

    if (input)
        free(input);

    return drc;
}

static void dbgshell_sigint_handler(int arg)
{
    DBGRET drc;

    sem_wait(&global_lock);
    g_shell_wait_input = 0;
    g_shell_ready = 0;
    drc = dbgshellcmd_exit(0, NULL);
    if (drc != DBGRET_TERMINATE)
    {
        dbgshell_print_message_dbgret("dbgshell_run", drc);
    }
    print_message(DBGSHELL_MSGINFO, "dbgshell_run", "Exiting...");
    sem_post(&global_lock);
    sem_destroy(&global_lock);
    IProgress_Release(g_progress);
    IMachine_Release(g_machine);
    ISession_UnlockMachine(g_session);
    if (g_session)
    {
        ISession_Release(g_session);
        g_session = NULL;
    }
    if (g_vbox)
    {
        IVirtualBox_Release(g_vbox);
        g_vbox = NULL;
    }
    if (g_vboxclient)
    {
        IVirtualBoxClient_Release(g_vboxclient);
        g_vboxclient = NULL;
    }
    g_pVBoxFuncs->pfnClientUninitialize();
    VBoxCGlueTerm();
    exit(0);
}

DBGRET dbgshell_start(IProgress *progress, IMachine *machine, ISession *session, IVirtualBox *vbox, IVirtualBoxClient *vbox_client)
{
    DBGRET drc;

    drc = init_dbgapi(session, &g_console, &g_debugger);
    if (!drc)
    {
        sem_init(&global_lock, 0, 1);
        g_progress = progress;
        g_machine = machine;
        g_session = session;
        g_vbox = vbox;
        g_vboxclient = vbox_client;
        signal(SIGINT, dbgshell_sigint_handler);
        clean_stdin();
        g_shell_ready = 1;
        print_message(DBGSHELL_MSGINFO, "dbgshell_start", "Shell started");
        print_message(DBGSHELL_MSGINFO, "dbgshell_start", "Default CPU is %u", g_cpuid);
        drc = dbgshell_run();
        g_shell_wait_input = 0;
        g_shell_ready = 0;
        sem_destroy(&global_lock);
    }

    return drc;
}








