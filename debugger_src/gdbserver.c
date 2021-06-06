#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#include "dbggdbserver.h"
#include "arch.h"
#include "utils.h"
#include "packets.h"
#include "gdb_signals.h"
#include "gdbserver.h"

#define FLNM "gdbserver.c"

uint8_t tmpbuf[0x160000];

void sigint_handler()
{
    sem_wait(&global_lock);
    set_singlestep_dbgapi(g_debugger, 1);
    sem_post(&global_lock);
}

void set_curr_thread(pid_t tid)
{
    sem_wait(&global_lock);
    g_cpuid = tid - 1;
    sem_post(&global_lock);
}

void wait4vmstop()
{
    uint8_t is_stopped;

    while (1)
    {
        sem_wait(&global_lock);
        get_singlestep_dbgapi(g_debugger, &is_stopped);
        sem_post(&global_lock);
        if (is_stopped)
        {
            break;
        }
        sleep(1);
    }

    sem_wait(&global_lock);
    wait4event_dbgapi(g_debugger);
    sem_post(&global_lock);
}


int process_xfer(const char* name, char* args)
{
    const char* mode = args;
    args = strchr(args, ':');
    *args++ = '\0';
    int ret = 0;

    if (!strcmp(name, "features") && !strcmp(mode, "read"))
        ret = write_packet(FEATURE_STR);

    return ret;
}

int process_query(char* payload)
{
    const char* name;
    char* args;
    int ret = 0;
    args = strchr(payload, ':');

    if (args)
        *args++ = '\0';

    name = payload;

    if (!strcmp(name, "C"))
    {
        snprintf((char *)tmpbuf, sizeof(tmpbuf), "QCp%02x.%02x",
                 1, g_cpuid+1);
        ret = write_packet((char *)tmpbuf);
    }

    if (!strcmp(name, "Attached"))
    {
        ret = write_packet("1");
    }

    if (!strcmp(name, "Offsets"))
        ret = write_packet("");

    if (!strcmp(name, "Supported"))
        ret = write_packet("PacketSize=16000;qXfer:features:read+;multiprocess+;swbreak+;hwbreak+");

    if (!strcmp(name, "Symbol"))
        ret = write_packet("");

    if (name == strstr(name, "ThreadExtraInfo"))
    {
        size_t hex_strlen, i;
        uint32_t cpuid;
        char hex_tmp[20], per_char_tmp[20];
        args = payload;
        args = 1 + strchr(args, ',');
        args++;
        sscanf(args, "%*x.%x", &cpuid);
        cpuid--;
        snprintf(hex_tmp, sizeof(hex_tmp), "%x", (uint8_t)cpuid);
        snprintf((char *)tmpbuf, sizeof(tmpbuf), "%02x%02x%02x%02x",
                (uint8_t)'C', (uint8_t)'P', (uint8_t)'U', (uint8_t)'#');
        hex_strlen = strlen(hex_tmp);
        for (i = 0; i < hex_strlen; i++)
        {
            snprintf(per_char_tmp, sizeof(per_char_tmp), "%02x", hex_tmp[i]);
            strcat((char *)tmpbuf, per_char_tmp);
        }
        ret = write_packet((char *)tmpbuf);
    }

    if (!strcmp(name, "TStatus"))
        ret = write_packet("");

    if (!strcmp(name, "Xfer"))
    {
        name = args;
        args = strchr(args, ':');
        *args++ = '\0';
        return process_xfer(name, args);
    }

    if (!strcmp(name, "fThreadInfo"))
    {
        uint32_t cpu_num;
        get_cpu_count_dbgapi(g_machine, &cpu_num);
        uint8_t pid_buf[20];
        strcpy((char *)tmpbuf, "m");

        for (uint32_t i = 0; i < cpu_num; i++)
        {
            snprintf((char *)pid_buf, sizeof(pid_buf), "p%02x.%02x,", 1, i+1);
            strcat((char *)tmpbuf, (char *)pid_buf);
        }

        tmpbuf[strlen((char *)tmpbuf) - 1] = '\0';
        ret = write_packet((char *)tmpbuf);
    }

    if (!strcmp(name, "sThreadInfo"))
        ret = write_packet("l");

    return ret;
}

int process_vpacket(char* payload)
{
    const char* name;
    char* args;
    int ret = 0;
    args = strchr(payload, ';');

    if (args)
        *args++ = '\0';

    name = payload;

    if (!strcmp("Cont", name))
    {
        if (args[0] == 'c')
        {
            set_singlestep_dbgapi(g_debugger, 0);

            enable_async_io();
            wait4vmstop();
            disable_async_io();

            sprintf((char *)tmpbuf, "T%02xthread:p%02x.%02x;", gdb_signal_from_host(SIGTRAP), 1, g_cpuid+1);
            ret = write_packet((char *)tmpbuf);
        }

        if (args[0] == 's')
        {
            assert(args[1] == ':');
            char* dot = strchr(args, '.');
            assert(dot);
            pid_t tid = strtol(dot + 1, NULL, 16);
            set_curr_thread(tid);
            step_into_dbgapi(g_debugger, g_cpuid);
            wait4vmstop();
            sprintf((char *)tmpbuf, "T%02xthread:p%02x.%02x;", gdb_signal_from_host(SIGTRAP), 1, g_cpuid + 1);
            ret = write_packet((char *)tmpbuf);
        }
    }

    if (!strcmp("Cont?", name))
        ret = write_packet("vCont;c;C;s;S;");

    if (!strcmp("Kill", name))
    {
        ret = write_packet("OK");
    }

    if (!strcmp("MustReplyEmpty", name))
        ret = write_packet("");

    if (name == strstr(name, "File:"))
    {
        write_packet("");
    }

    return ret;
}


int vbox_reg_map[] =
{0, 3, 1, 2, 6, 7, 5, 4, 8, 9, 10, 11, 12, 13, 14, 15, 40, 41, 16, 36, 20, 24, 28, 32};
char* vbox_reg_name_map[] =
{
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rip",
    "rflags",
    "cs",
    "ss",
    "ds",
    "es",
    "fs",
    "gs"
};

int process_packet()
{
    DBGRET drc;
    uint8_t* inbuf = inbuf_get();
    int inbuf_size = inbuf_end();

    while (inbuf[0] == '+' || inbuf[0] == INTERRUPT_CHAR)
    {
        inbuf++;
        inbuf_size--;
    }

    uint8_t* packetend_ptr = (uint8_t*)memchr(inbuf, '#',
                             inbuf_size);
    int packetend = packetend_ptr - inbuf;

    assert('$' == inbuf[0]);
    char request = inbuf[1];
    char* payload = (char*)&inbuf[2];
    inbuf[packetend] = '\0';
    uint8_t checksum = 0;
    // uint8_t checksum_str[3];
    int ret = 0;

    for (int i = 1; i < packetend; i++)
        checksum += inbuf[i];

    assert(checksum == (hex(inbuf[packetend + 1]) << 4 | hex(
                            inbuf[packetend + 2])));

    switch (request)
    {
    case 'D':
    /**
     * @todo: detach debugger
     */
        return -1;

    case 'g':
    {
        char** rg_names;
        char** rg_values;
        ULONG rg_num;
        uint8_t regbuf[20];
        tmpbuf[0] = '\0';
        sem_wait(&global_lock);
        drc = get_registers_dbgapi(g_debugger, g_cpuid, &rg_names, &rg_values, &rg_num);
        sem_post(&global_lock);
        if (!drc)
        {
            for (int i = 0; i < ARCH_REG_NUM; i++)
            {
                uint32_t reg32;
                uint64_t reg64;

                sscanf(rg_values[vbox_reg_map[i]], "0x%lx", &reg64);

                if (regs_map[i].size == 4)
                {
                    reg32 = (uint32_t)reg64;
                    mem2hex((void *)&reg32, (char *)regbuf, regs_map[i].size);
                }
                else
                {
                    mem2hex((void *)&reg64, (char *)regbuf, regs_map[i].size);
                }

                regbuf[regs_map[i].size * 2] = '\0';
                strcat((char *)tmpbuf, (char *)regbuf);
            }
            free_get_registers_array_dbgapi(rg_names, rg_values, rg_num);
        }
        else
        {
            sem_wait(&global_lock);
            dbgshell_print_message_dbgret("process_packet", drc);
            sem_post(&global_lock);
            return -1;
        }

        ret = write_packet((char *)tmpbuf);
        break;
    }

    case 'H':
        if ('g' == *payload++)
        {
            pid_t tid;
            char* dot = strchr(payload, '.');
            assert(dot);
            tid = strtol(dot, NULL, 16);

            if (tid > 0)
                set_curr_thread(tid);
        }

        ret = write_packet("OK");
        break;

    case 'm':
    {
        size_t maddr, mlen;
        uint8_t* mem_data;
        uint32_t out_byte_num;
        assert(sscanf(payload, "%zx,%zx", &maddr, &mlen) == 2);

        if (mlen * 2 >= sizeof(tmpbuf))
        {
            sem_wait(&global_lock);
            print_message(DBGSHELL_MSGERRO, "process_packet", "Buffer overflow");
            sem_post(&global_lock);
            return -1;
        }

        sem_wait(&global_lock);
        drc = read_virtual_memory_dbgapi(g_debugger, g_cpuid, maddr, mlen, &out_byte_num, &mem_data);
        sem_post(&global_lock);
        if (drc)
        {
            sprintf((char *)tmpbuf, "E%02x", 0x05);
        }
        else
        {
            if (out_byte_num >= mlen)
            {
                mem2hex((char *)mem_data, (char *)tmpbuf, mlen);
            }
            else
            {
                sprintf((char *)tmpbuf, "E%02x", 0x05);
            }

            free_read_memory_array_dbgapi(mem_data);
        }

        tmpbuf[mlen * 2] = '\0';
        ret = write_packet((char *)tmpbuf);
        break;
    }

    case 'M':
    {
        uint8_t *mdata;
        size_t maddr, mlen;
        int offset;
        assert(sscanf(payload, "%zx,%zx:%n", &maddr, &mlen, &offset) == 2);
        payload += offset;

        mdata = (uint8_t *)malloc(mlen * sizeof(uint8_t));
        hex2mem(payload, (void*)mdata, mlen);

        sem_wait(&global_lock);
        drc = write_virtual_memory_dbgapi(g_debugger, g_cpuid, maddr, mlen, mdata);
        sem_post(&global_lock);

        if (drc)
        {
            sprintf((char *)tmpbuf, "E%02x", 0x05);
        }
        else
        {
            sprintf((char *)tmpbuf, "OK");
        }

        free(mdata);
        ret = write_packet((char *)tmpbuf);
        break;
    }

    case 'p':
    {
        int i = strtol(payload, NULL, 16);
        uint32_t reg32;
        uint64_t reg64;
        char** rg_names;
        char** rg_values;
        ULONG rg_num;

        if (i >= ARCH_REG_NUM)
        {
            ret = write_packet("E01");
            break;
        }

        sem_wait(&global_lock);
        drc = get_registers_dbgapi(g_debugger, g_cpuid, &rg_names, &rg_values, &rg_num);
        sem_post(&global_lock);
        if (!drc)
        {
            sscanf(rg_values[vbox_reg_map[i]], "0x%lx", &reg64);

            if (regs_map[i].size == 4)
            {
                reg32 = (uint32_t)reg64;
                mem2hex((void *)&reg32, (char *)tmpbuf, regs_map[i].size);
            }
            else
            {
                mem2hex((void *)&reg64, (char *)tmpbuf, regs_map[i].size);
            }

            tmpbuf[regs_map[i].size * 2] = '\0';

            free_get_registers_array_dbgapi(rg_names, rg_values, rg_num);
        }
        else
        {
            sem_wait(&global_lock);
            dbgshell_print_message_dbgret("process_packet", drc);
            sem_post(&global_lock);
            return -1;
        }

        ret = write_packet((char *)tmpbuf);
        break;
    }

    case 'P':
    {
        int i = strtol(payload, &payload, 16);
        char reg_data_buf[40];
        assert('=' == *payload++);

        if (i >= ARCH_REG_NUM)
        {
            ret = write_packet("E01");
            break;
        }

        uint64_t regdata = 0;
        hex2mem(payload, (void*)&regdata, sizeof(regdata));

        snprintf(reg_data_buf, sizeof(reg_data_buf), "%lx", regdata);

        drc = set_register_dbgapi(g_debugger, g_cpuid, vbox_reg_name_map[i], reg_data_buf);
        if (drc)
        {
            ret = write_packet("E01");
            break;
        }

        ret = write_packet("OK");
        break;
    }

    case 'q':
        process_query(payload);
        break;

    case 'T':
        ret = write_packet("OK");
        break;

    case 'v':
        process_vpacket(payload);
        break;

    case 'X':
    {
        uint8_t *mdata;
        size_t maddr, mlen;
        int offset, new_len;
        assert(sscanf(payload, "%zx,%zx:%n", &maddr, &mlen,
                      &offset) == 2);
        payload += offset;
        new_len = unescape(payload, (char*)packetend_ptr - payload);
        assert(new_len == mlen);

        mdata = (uint8_t *)malloc(sizeof(uint8_t) * mlen);
        memcpy((void *)mdata, payload, mlen);

        sem_wait(&global_lock);
        drc = write_virtual_memory_dbgapi(g_debugger, g_cpuid, maddr, mlen, mdata);
        sem_post(&global_lock);

        if (drc)
        {
            sprintf((char *)tmpbuf, "E%02x", 0x05);
        }
        else
        {
            sprintf((char *)tmpbuf, "OK");
        }

        free(mdata);
        ret = write_packet((char *)tmpbuf);
        break;
    }

    case 'Z':
    {
        size_t type, addr, length;
        assert(sscanf(payload, "%zx,%zx,%zx", &type, &addr,
                      &length) == 3);
        if (length == 0)
            length = 1;

        sem_wait(&global_lock);
        switch (type)
        {
        case 0:
            drc = add_sw_bp_dbgapi(g_debugger, NULL, g_cpuid, addr, 0, 0, 0);
            break;
        case 1:
            drc = add_hw_bp_dbgapi(g_debugger, NULL, addr, 0, 0, 0);
            break;
        case 2:
            drc = add_wo_wp_dbgapi(g_debugger, NULL, addr, 0, 0, 0, length);
            break;
        case 3:
        case 4:
            drc = add_rw_wp_dbgapi(g_debugger, NULL, addr, 0, 0, 0, length);
            break;
        default:
            ret = write_packet("");
            goto END;
        }
        sem_post(&global_lock);

        if (drc)
        {
            ret = write_packet("E01");
        }
        else
        {
            ret = write_packet("OK");
        }

        break;
    }

    case 'z':
    {
        size_t type, addr, length;
        uint64_t is_hard_brkp, hard_type;
        int64_t ret_ibp;
        uint32_t ibp;
        assert(sscanf(payload, "%zx,%zx,%zx", &type, &addr,
                      &length) == 3);
        if (length == 0)
            length = 1;

        switch (type)
        {
        case 0:
            is_hard_brkp = 0;
            hard_type = 0;
            break;
        case 1:
            is_hard_brkp = 1;
            hard_type = 0;
            break;
        case 2:
            is_hard_brkp = 1;
            hard_type = 2;
            break;
        case 3:
        case 4:
            is_hard_brkp = 1;
            hard_type = 1;
            break;
        default:
            ret = write_packet("");
            goto END;
        }

        sem_wait(&global_lock);
        ret_ibp = bp_get_ibp(is_hard_brkp, hard_type, addr, length);
        sem_post(&global_lock);
        if (ret_ibp < 0)
        {
            ret = write_packet("OK");
            break;
        }
        ibp = (uint32_t)ret_ibp;
        sem_wait(&global_lock);
        drc = del_breakpoint_dbgapi(g_debugger, ibp);
        sem_post(&global_lock);

        if (drc)
        {
            ret = write_packet("E01");
        }
        else
        {
            ret = write_packet("OK");
        }

        break;
    }

    case '?':
        ret = write_packet("S05");
        break;

    default:
        ret = write_packet("");
    }

END:
    inbuf_erase_head(packetend + 3);
    return ret;
}

int get_request()
{
    int ret;

    while (true)
    {
        sem_wait(&global_lock);
        wait4event_dbgapi(g_debugger);
        sem_post(&global_lock);
        ret = read_packet();
        if (ret < 0)
            return ret;
        ret = process_packet();
        if (ret < 0)
            return ret;
        ret = write_flush();
        if (ret < 0)
            return ret;
    }
}

int launch_server()
{
    sigint_handler();
    return get_request();
}
