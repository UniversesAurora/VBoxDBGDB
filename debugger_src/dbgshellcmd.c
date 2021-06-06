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


#include "dbgshellcmd.h"

#define FLNM "dbgshellcmd.c"


pthread_t g_gdbserver_pthread_t;


/**
 * From VirtualBox Debugger
 */


/**
 * Checks for a hexadecimal digit.
 *
 * @returns true / false.
 * @param   ch      The character to test.
 */
int8_t dbgshell_is_hex(int ch)
{
    return (unsigned)ch - 0x30 < 10U /* 30..39 (0-9) */
        || (unsigned)ch - 0x41 < 6   /* 41..46 (A-F) */
        || (unsigned)ch - 0x61 < 6;  /* 61..66 (a-f) */
}


DBGRET dbgshell_eval_num(const char *pachExpr, size_t cchExpr, unsigned uBase, uint64_t* pArg)
{
    /*
     * Empty expressions cannot be valid numbers.
     */
    if (!cchExpr)
        return DBGRET_EPARSE;

    /*
     * Convert to number.
     */
    uint64_t    u64 = 0;
    while (cchExpr-- > 0)
    {
        char const ch = *pachExpr;
        uint64_t    u64Prev = u64;
        unsigned    u = ch - '0';
        if (u < 10 && u < uBase)
            u64 = u64 * uBase + u;
        else if (ch >= 'a' && (u = ch - ('a' - 10)) < uBase)
            u64 = u64 * uBase + u;
        else if (ch >= 'A' && (u = ch - ('A' - 10)) < uBase)
            u64 = u64 * uBase + u;
        else
            return DBGRET_EPARSE;

        /* check for overflow - ARG!!! How to detect overflow correctly!?!?!? */
        if (u64Prev != u64 / uBase)
            return DBGRET_EPARSE;

        /* next */
        pachExpr++;
    }

    /*
     * Initialize the argument.
     */
    *pArg = u64;

    return DBGRET_SUCCESS;
}


/**
 * dbgcEvalSubUnary worker that handles simple numeric or pointer expressions.
 *
 * @returns VBox status code. pResult contains the result on success.
 * @param   pszExpr     The expression string.
 * @param   cchExpr     The length of the expression.
 * @param   pResult     Where to store the result of the expression evaluation.
 */
DBGRET dbgshell_eval(char *pszExpr, size_t cchExpr, void* pResult)
{
    DBGRET drc = DBGRET_EPARSE;
    uint64_t uresult;
    uint8_t is_neg = 0;

    if (!pszExpr || !pResult)
        return DBGRET_ENULLPTR;

    if (*pszExpr == '-')
    {
        is_neg = 1;
        cchExpr--;
        pszExpr++;
    }
    else if (*pszExpr == '+')
    {
        cchExpr--;
        pszExpr++;
    }

    char const  ch  = pszExpr[0];
    char const  ch2 = pszExpr[1];

    /* 0x<hex digits> */
    if (ch == '0' && (ch2 == 'x' || ch2 == 'X'))
        drc = dbgshell_eval_num(pszExpr + 2, cchExpr - 2, 16, &uresult);

    /* <hex digits>h */
    else if (dbgshell_is_hex(*pszExpr) && (pszExpr[cchExpr - 1] == 'h' || pszExpr[cchExpr - 1] == 'H'))
    {
        pszExpr[cchExpr] = '\0';
        drc = dbgshell_eval_num(pszExpr, cchExpr - 1, 16, &uresult);
    }

    /* 0i<decimal digits> */
    else if (ch == '0' && (ch2 == 'i' || ch2 == 'I'))
        drc = dbgshell_eval_num(pszExpr + 2, cchExpr - 2, 10, &uresult);

    /* 0t<octal digits> */
    else if (ch == '0' && (ch2 == 't' || ch2 == 'T'))
        drc = dbgshell_eval_num(pszExpr + 2, cchExpr - 2, 8, &uresult);

    /* 0y<binary digits> */
    else if (ch == '0' && (ch2 == 'y' || ch2 == 'Y'))
        drc = dbgshell_eval_num(pszExpr + 2, cchExpr - 2, 2, &uresult);

    /* Hex number? */
    else
    {
        unsigned off = 0;
        while (off < cchExpr && (dbgshell_is_hex(pszExpr[off]) || pszExpr[off] == '`'))
            off++;
        if (off == cchExpr)
            drc = dbgshell_eval_num(pszExpr, cchExpr, 16, &uresult);
    }

    if (is_neg)
    {
        *((int64_t *)pResult) = 0 - (int64_t)uresult;
    }
    else
    {
        *((uint64_t *)pResult) = uresult;
    }

    return drc;
}

DBGRET dbgshellcmd_exit(unsigned long argc, char** argv)
{
    DBGRET drc;
    drc = dbgshellcmd_gdbclose(argc, argv);
    drc = release_dbgapi(g_console, g_debugger);

    if (drc == DBGRET_SUCCESS)
        drc = DBGRET_TERMINATE;

    return drc;
}

DBGRET dbgshellcmd_help(unsigned long argc, char** argv)
{
    uint64_t i;

    for (i = 0; i < dbgshell_cmds_sz; i++)
    {
        if (argc == 1)
        {
            printf("%-10s%-30s%s\n",
            dbgshell_cmds[i].cmd_name, dbgshell_cmds[i].cmd_syntax, dbgshell_cmds[i].cmd_description);
        }
        else if (strcmp(argv[1], dbgshell_cmds[i].cmd_name) == 0)
        {
            printf("%-10s%-30s%s\n",
            dbgshell_cmds[i].cmd_name, dbgshell_cmds[i].cmd_syntax, dbgshell_cmds[i].cmd_description);
            break;
        }
    }

    if (argc != 1 && i == dbgshell_cmds_sz)
    {
        print_message(DBGSHELL_MSGWARN, "dbgshell_exec_cmd", "Command %s not found", argv[1]);
    }

    return DBGRET_SUCCESS;
}

DBGRET dbgshellcmd_cpu(unsigned long argc, char **argv)
{
    uint64_t cpuid_wide;
    DBGRET drc;

    if (argc == 1)
    {
        printf("Current CPU ID is #%u\n", g_cpuid);
        drc = DBGRET_SUCCESS;
    }
    else
    {
        drc = dbgshell_eval(argv[1], strlen(argv[1]), &cpuid_wide);
        if (drc)
        {
            dbgshell_print_message_dbgret("dbgshellcmd_cpu", drc);
        }
        else
        {
            uint32_t old_cpuid = g_cpuid;
            uint32_t cpu_num;
            get_cpu_count_dbgapi(g_machine, &cpu_num);
            if (((uint32_t)cpuid_wide) >= cpu_num)
            {
                printf("CPU ID #%u is out of range, highest CPU ID is #%u\n", (uint32_t)cpuid_wide, cpu_num-1);
                drc = DBGRET_ECMDFAIL;
            }
            else
            {
                g_cpuid = (uint32_t)cpuid_wide;
                printf("Set CPU ID from #%u to #%u\n", old_cpuid, g_cpuid);
            }
        }
    }

    return drc;
}

DBGRET dbgshellcmd_rg_show(char* rg_name)
{
    DBGRET drc;
    if (rg_name)
    {
        // todo: query one rg
        print_message(DBGSHELL_MSGWARN, "dbgshellcmd_rg_show", "Query one register currently not implemented");
        drc = DBGRET_SUCCESS;
    }
    else
    {
        char** rg_names;
        char** rg_values;
        ULONG rg_num;
        drc = get_registers_dbgapi(g_debugger, g_cpuid, &rg_names, &rg_values, &rg_num);
        if (!drc)
        {
            for (ULONG i = 0; i < rg_num; i++)
            {
                if (rg_names[i][0])
                {
                    printf("%s: %s\n", rg_names[i], rg_values[i]);
                }
            }

            free_get_registers_array_dbgapi(rg_names, rg_values, rg_num);
        }
    }

    return drc;
}

DBGRET dbgshellcmd_rg(unsigned long argc, char** argv)
{
    DBGRET drc;
    if (argc == 1)
    {
        drc = dbgshellcmd_rg_show(NULL);
    }
    else if (argc == 2)
    {
        drc = dbgshellcmd_rg_show(argv[1]);
    }
    else
    {
        drc = set_register_dbgapi(g_debugger, g_cpuid, argv[1], argv[2]);
        if (drc)
        {
            dbgshell_print_message_dbgret("dbgshellcmd_rg", drc);
        }
    }

    return drc;
}

DBGRET dbgshellcmd_cvp(unsigned long argc, char** argv)
{
    uint64_t vir_addr, phy_addr;
    DBGRET drc;

    if (argc < 2)
    {
        return DBGRET_EARGTOOFEW;
    }

    drc = dbgshell_eval(argv[1], strlen(argv[1]), &vir_addr);
    if (drc)
    {
        goto END;
    }

    drc = v2pa_dbgapi(g_debugger, g_cpuid, vir_addr, &phy_addr);
    if (!drc)
    {
        printf("Virtual Address: 0x%016lx\nPhysical Address: 0x%016lx\n", vir_addr, phy_addr);
    }

END:
    return drc;
}

uint32_t dmp_prev_line_count = 5;
uint32_t dmv_prev_line_count = 5;
uint64_t dmp_prev_addr = 0;
uint64_t dmv_prev_addr = 0;

void print_memory(uint64_t addr, uint32_t byte_num, uint8_t* mem_data)
{
    uint64_t unaligned_addr = addr, align_offset;
    uint32_t walk = 0, line_walk = 0, line_guard = byte_num;
    uint32_t remain_word_count;
    uint8_t special_start, special_end = 0;

    addr &= 0xfffffffffffffff0UL;
    align_offset = unaligned_addr - addr;

    if (byte_num == 0)
        return;

    special_start = unaligned_addr & 0x1;

    if ((byte_num + special_start) % 2)
    {
        special_end = 1;
        byte_num--;
    }

    remain_word_count = (8 - (((line_guard + align_offset) % 16) / 2 + special_end)) % 8;

    printf("Address              0    2     4    6     8    A     C    E   0 2 4 6 8 A C E \n");
    for (line_walk = 0; line_walk < line_guard; )
    {
        uint32_t next_line_pos = walk + 16 - (line_walk ? 0 : align_offset);
        uint32_t guard = next_line_pos < byte_num ? next_line_pos : byte_num;
        uint32_t ascii_guard = next_line_pos < line_guard ? next_line_pos : line_guard;
        uint8_t space_flip = 0;

        printf("%016lx: ", addr);
        walk = line_walk;

        if (align_offset && line_walk == 0)
        {
            uint32_t i = align_offset / 2;
            while (i > 0)
            {
                printf("    %s", space_flip ? "  " : " ");
                space_flip = !space_flip;
                i--;
            }

            if (special_start)
            {
                printf("%02x??%s", mem_data[walk],
                        space_flip ? "  " : (walk < line_guard - 1 ? ":" : " "));
                space_flip = !space_flip;
                walk++;
            }
        }

        for (; walk < guard; walk+=2)
        {
            printf("%04x%s", *((uint16_t *)(mem_data + walk)),
                    space_flip ? "  " : (walk == byte_num - 2 && !special_end ? " " : ":"));
            space_flip = !space_flip;
        }

        if (walk == byte_num)
        {
            if (special_end && (walk - line_walk < (line_walk ? 16 : 16 - align_offset)))
            {
                printf("??%02x%s", mem_data[walk], space_flip ? "  " : " ");
                space_flip = !space_flip;
                walk++;
            }

            if (!special_end || (walk - line_walk < (line_walk ? 16 : 16 - align_offset)))
            {
                for (uint32_t i = 0; i < remain_word_count; i++)
                {
                    printf("    %s", space_flip ? "  " : " ");
                    space_flip = !space_flip;
                }
            }
        }

        printf(" ");
        /** Print ascii table **/
        if (align_offset && line_walk == 0)
        {
            for (uint32_t i = 0; i < align_offset; i++)
            {
                printf(" ");
            }
        }

        for (walk = line_walk; walk < ascii_guard; walk++)
        {
            printf("%c", (mem_data[walk] > 32 && mem_data[walk] < 127 ? mem_data[walk] : ' '));
        }

        if (walk == line_guard)
        {
            uint32_t i = (16 - (line_guard + align_offset) % 16) % 16;
            while (i--)
            {
                printf(" ");
            }
        }


        printf("\n");
        line_walk = walk;
        addr += 16;
    }
}

DBGRET dbgshellcmd_dm(uint8_t is_virtual, unsigned long argc, char** argv)
{
    uint32_t line_count = 5, byte_num, out_byte_num;
    uint64_t line_count_wide;
    uint64_t addr;
    uint8_t* mem_data;
    DBGRET drc;

    if (argc == 1)
    {
        line_count = is_virtual ? dmv_prev_line_count : dmp_prev_line_count;
        addr = is_virtual ? dmv_prev_addr : dmp_prev_addr;
    }

    else if (argc == 3)
    {
        drc = dbgshell_eval(argv[2], strlen(argv[2]), &line_count_wide);
        if (drc || line_count_wide == 0)
            goto END;
        line_count = (uint32_t)line_count_wide;
    }

    if (argc > 1)
    {
        drc = dbgshell_eval(argv[1], strlen(argv[1]), &addr);
        if (drc)
            goto END;
    }

    byte_num = line_count * 16 - (addr - (addr & 0xfffffffffffffff0UL));


    if (is_virtual)
    {
        dmv_prev_line_count = line_count;
        dmv_prev_addr = addr;
        drc = read_virtual_memory_dbgapi(g_debugger, g_cpuid, addr, byte_num, &out_byte_num, &mem_data);
    }
    else
    {
        dmp_prev_line_count = line_count;
        dmp_prev_addr = addr;
        drc = read_physical_memory_dbgapi(g_debugger, addr, byte_num, &out_byte_num, &mem_data);
    }
    if (drc)
        goto END;

    print_memory(addr, out_byte_num, mem_data);

    free_read_memory_array_dbgapi(mem_data);

END:
    return drc;
}

DBGRET dbgshellcmd_dmp(unsigned long argc, char** argv)
{
    return dbgshellcmd_dm(0, argc, argv);
}

DBGRET dbgshellcmd_dmv(unsigned long argc, char** argv)
{
    return dbgshellcmd_dm(1, argc, argv);
}


DBGRET dbgshellcmd_em(uint8_t is_virtual, unsigned long argc, char** argv, uint32_t unit_sz)
{
    uint8_t *data_arr;
    uint64_t data_num = argc - 2;
    uint64_t addr, walk_data;
    DBGRET drc;

    drc = dbgshell_eval(argv[1], strlen(argv[1]), &addr);
    if (drc)
    {
        goto END;
    }

    data_arr = malloc(sizeof(uint8_t)*unit_sz*data_num);

    if (!data_arr)
    {
        drc = DBGRET_EOUTOFMEM;
        goto END;
    }

    for (walk_data = 0; walk_data < data_num; walk_data++)
    {
        uint64_t data;
        drc = dbgshell_eval(argv[walk_data+2], strlen(argv[walk_data+2]), &data);
        if (drc)
        {
            goto FREE;
        }

        switch (unit_sz)
        {
        case 1:
            ((uint8_t *)data_arr)[walk_data] = data;
            break;
        case 2:
            ((uint16_t *)data_arr)[walk_data] = data;
            break;
        case 4:
            ((uint32_t *)data_arr)[walk_data] = data;
            break;
        case 8:
            ((uint64_t *)data_arr)[walk_data] = data;
            break;
        default:
            print_message(DBGSHELL_MSGERRO, "dbgshellcmd_em", "Invalid unit size");
            drc = DBGRET_ECMDFAIL;
            goto FREE;
        }
    }

    if (is_virtual)
    {
        drc = write_virtual_memory_dbgapi(g_debugger, g_cpuid, addr, unit_sz * data_num, data_arr);
    }
    else
    {
        drc = write_physical_memory_dbgapi(g_debugger, addr, unit_sz * data_num, data_arr);
    }


FREE:
    free(data_arr);
END:
    return drc;
}

DBGRET dbgshellcmd_empb(unsigned long argc, char** argv)
{
    return dbgshellcmd_em(0, argc, argv, 1);
}

DBGRET dbgshellcmd_empw(unsigned long argc, char** argv)
{
    return dbgshellcmd_em(0, argc, argv, 2);
}

DBGRET dbgshellcmd_empd(unsigned long argc, char** argv)
{
    return dbgshellcmd_em(0, argc, argv, 4);
}

DBGRET dbgshellcmd_empq(unsigned long argc, char** argv)
{
    return dbgshellcmd_em(0, argc, argv, 8);
}


DBGRET dbgshellcmd_emvb(unsigned long argc, char** argv)
{
    return dbgshellcmd_em(1, argc, argv, 1);
}

DBGRET dbgshellcmd_emvw(unsigned long argc, char** argv)
{
    return dbgshellcmd_em(1, argc, argv, 2);
}

DBGRET dbgshellcmd_emvd(unsigned long argc, char** argv)
{
    return dbgshellcmd_em(1, argc, argv, 4);
}

DBGRET dbgshellcmd_emvq(unsigned long argc, char** argv)
{
    return dbgshellcmd_em(1, argc, argv, 8);
}

void check_cpu_count_one_print_warn()
{
    DBGRET drc;
    uint32_t count;
    drc = get_cpu_count_dbgapi(g_machine, &count);
    if (drc)
    {
        print_message(DBGSHELL_MSGWARN, "check_cpu_count_one_print_warn", "Get CPU count failed");
        dbgshell_print_message_dbgret("check_cpu_count_one_print_warn", drc);
        return;
    }

    if (count > 1)
    {
        printf("WARING!!! Attemtting to control instruction flow on a Virtual Machine that has MORE THAN ONE CORE!\n");
        printf("THIS MAY LEAD TO UNPREDICTABLE SITUATION!!!\n");
    }

    return;
}

DBGRET dbgshellcmd_g(unsigned long argc, char** argv)
{
    check_cpu_count_one_print_warn();
    return set_singlestep_dbgapi(g_debugger, 0);
}

DBGRET dbgshellcmd_stop(unsigned long argc, char** argv)
{
    check_cpu_count_one_print_warn();
    return set_singlestep_dbgapi(g_debugger, 1);
}

DBGRET dbgshellcmd_so(unsigned long argc, char** argv)
{
    return step_over_dbgapi(g_debugger, g_cpuid);
}

DBGRET dbgshellcmd_si(unsigned long argc, char** argv)
{
    return step_into_dbgapi(g_debugger, g_cpuid);
}

DBGRET dbgshellcmd_ba(unsigned long argc, char** argv)
{
    uint64_t params[7];
    DBGRET drc;
    uint32_t ibp;

    if (argc < 8)
    {
        return DBGRET_EARGTOOFEW;
    }

    for (int i = 0; i < RT_ELEMENTS(params); i++)
    {
        drc = dbgshell_eval(argv[i+1], strlen(argv[i+1]), &params[i]);
        if (drc)
        {
            goto END;
        }
    }

    drc = add_breakpoint_dbgapi(g_debugger, params[0], params[1], g_cpuid, params[2], params[3], params[4], params[5], params[6], &ibp);
    if (drc)
    {
        print_message(DBGSHELL_MSGERRO, "dbgshellcmd_ba", "Failed to add breakpoint");
    }
    else
    {
        printf("Breakpoint %u added\n", ibp);
    }

END:
    return drc;
}

DBGRET dbgshellcmd_bc(unsigned long argc, char** argv)
{
    DBGRET drc;
    uint64_t ibp_wide;
    uint32_t ibp;

    if (argc < 2)
    {
        return DBGRET_EARGTOOFEW;
    }

    drc = dbgshell_eval(argv[1], strlen(argv[1]), &ibp_wide);
    if (drc)
    {
        goto END;
    }
    ibp = (uint32_t)ibp_wide;

    drc = del_breakpoint_dbgapi(g_debugger, ibp);
    if (drc)
    {
        print_message(DBGSHELL_MSGERRO, "dbgshellcmd_bc", "Failed to delete breakpoint");
    }
    else
    {
        printf("Breakpoint %u deleted\n", ibp);
    }

END:
    return drc;
}

DBGRET dbgshellcmd_bl(unsigned long argc, char** argv)
{
    pbp_node pbp = bp_head;

    if (bp_head)
    {
        printf("ibp\taddress\t\tis_hard_brkp hard_type cpu_id hit_trigger has_hit_disable hit_disable access_sz\n");
    }
    else
    {
        printf("Currently no breakpoint\n");
    }

    for (; pbp; pbp = pbp->next)
    {
        printf("%u\t0x%016lx\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\n", pbp->ibp,
               pbp->address, pbp->is_hard_brkp, pbp->hard_type, pbp->cpu_id,
               pbp->hit_trigger, pbp->has_hit_disable, pbp->hit_disable, pbp->access_sz);
    }

    return DBGRET_SUCCESS;
}


DBGRET dbgshellcmd_gdbopen(unsigned long argc, char** argv)
{
    DBGRET drc;
    uint64_t port_wide;

    dbgshellcmd_gdbclose(argc, argv);

    if (argc > 1)
    {
        drc = dbgshell_eval(argv[1], strlen(argv[1]), &port_wide);
        if (drc)
        {
            goto END;
        }
        g_gdbserver_port = (uint16_t)port_wide;
    }

    if (pthread_create(&g_gdbserver_pthread_t, NULL, start_dbggdbserver, NULL) == 0)
    {
        g_gdbserver_running = 1;
        drc = DBGRET_SUCCESS;
    }
    else
    {
        print_message(DBGSHELL_MSGWARN, "dbgshellcmd_gdbo", "Exec pthread_create() failed");
        print_sys_error(DBGSHELL_MSGERRO, "dbgshellcmd_gdbo", "pthread_create");
        drc = DBGRET_ECMDFAIL;
    }

END:
    return drc;
}

DBGRET dbgshellcmd_gdbclose(unsigned long argc, char** argv)
{
    if (g_gdbserver_running)
    {
        if (pthread_cancel(g_gdbserver_pthread_t) != 0)
        {
            print_message(DBGSHELL_MSGWARN, "dbgshellcmd_gdbo", "Exec pthread_cancel() failed");
            print_sys_error(DBGSHELL_MSGERRO, "dbgshellcmd_gdbo", "pthread_cancel");
        }
        g_gdbserver_running = 0;
    }

    return DBGRET_SUCCESS;
}

