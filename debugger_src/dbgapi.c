#include "dbgapi.h"


#define FLNM "dbgapi.c"


DBGRET init_dbgapi(ISession* session, IConsole** console, IMachineDebugger** debugger)
{
    HRESULT rc = ISession_get_Console(session, console);
    if (SUCCEEDED(rc) && *console)
    {
        rc = IConsole_get_Debugger(*console, debugger);

        if (SUCCEEDED(rc) && *debugger)
        {
            BSTR name;
            BSTR plugin_name;
            g_pVBoxFuncs->pfnUtf8ToUtf16("all", &name);
            rc = IMachineDebugger_LoadPlugIn(*debugger, name, &plugin_name);
            g_pVBoxFuncs->pfnUtf16Free(name);
            g_pVBoxFuncs->pfnComUnallocString(plugin_name);
            if (FAILED(rc))
            {
                print_error("init_dbgapi", "IMachineDebugger_LoadPlugIn", rc);
                IMachineDebugger_Release(*debugger);
                IConsole_Release(*console);
                return DBGRET_EINIT;
            }

            return DBGRET_SUCCESS;
        }
        else
        {
            print_error("init_dbgapi", "IConsole_get_Debugger", rc);
            IConsole_Release(*console);
            return DBGRET_EINIT;
        }
    }
    else
    {
        print_error("init_dbgapi", "ISession_get_Console", rc);
        return DBGRET_EINIT;
    }
}

DBGRET release_dbgapi(IConsole* console, IMachineDebugger* debugger)
{
    BSTR name;
    g_pVBoxFuncs->pfnUtf8ToUtf16("all", &name);
    HRESULT rc = IMachineDebugger_UnloadPlugIn(debugger, name);
    g_pVBoxFuncs->pfnUtf16Free(name);
    if (FAILED(rc))
    {
        print_error("release_dbgapi", "IMachineDebugger_UnloadPlugIn", rc);
        return DBGRET_ERELEASE;
    }
    IMachineDebugger_Release(debugger);
    IConsole_Release(console);
    return DBGRET_SUCCESS;
}


DBGRET get_cpu_count_dbgapi(IMachine* machine, uint32_t* cpu_count)
{
    IMachine_get_CPUCount(machine, cpu_count);
    return DBGRET_SUCCESS;
}



DBGRET get_singlestep_dbgapi(IMachineDebugger* debugger, uint8_t* sstep)
{
    PRBool prsstep = PR_FALSE;
    HRESULT rc = IMachineDebugger_get_SingleStep(debugger, &prsstep);
    if (FAILED(rc))
    {
        print_error("get_singlestep_dbgapi", "IMachineDebugger_get_SingleStep", rc);
        return DBGRET_EGENERAL;
    }
    *sstep = prsstep ? 1 : 0;
    return DBGRET_SUCCESS;
}

DBGRET set_singlestep_dbgapi(IMachineDebugger* debugger, uint8_t sstep)
{
    PRBool prsstep = sstep ? PR_TRUE : PR_FALSE;
    HRESULT rc = IMachineDebugger_put_SingleStep(debugger, prsstep);
    if (FAILED(rc))
    {
        print_error("set_singlestep_dbgapi", "IMachineDebugger_put_SingleStep", rc);
        return DBGRET_EGENERAL;
    }

    return DBGRET_SUCCESS;
}

DBGRET get_registers_dbgapi(IMachineDebugger* debugger, uint32_t cpuid, char*** reg_name_out, char*** reg_value_out, ULONG* reg_num)
{
    SAFEARRAY* reg_name_s = g_pVBoxFuncs->pfnSafeArrayOutParamAlloc();
    SAFEARRAY* reg_value_s = g_pVBoxFuncs->pfnSafeArrayOutParamAlloc();

    HRESULT rc = IMachineDebugger_GetRegisters(debugger, cpuid, ComSafeArrayAsOutTypeParam(reg_name_s, BSTR), ComSafeArrayAsOutTypeParam(reg_value_s, BSTR));
    if (SUCCEEDED(rc))
    {
        BSTR *reg_name = NULL;
        BSTR *reg_value = NULL;
        ULONG reg_name_sz = 0, reg_value_sz = 0;
        ULONG i;

        g_pVBoxFuncs->pfnSafeArrayCopyOutParamHelper((void **)&reg_name, &reg_name_sz, VT_BSTR, reg_name_s);
        g_pVBoxFuncs->pfnSafeArrayCopyOutParamHelper((void **)&reg_value, &reg_value_sz, VT_BSTR, reg_value_s);
        g_pVBoxFuncs->pfnSafeArrayDestroy(reg_name_s);
        g_pVBoxFuncs->pfnSafeArrayDestroy(reg_value_s);
        *reg_num = reg_name_sz / sizeof(reg_name[0]);

        *reg_name_out = (char **)malloc((*reg_num) * sizeof(char *));
        *reg_value_out = (char **)malloc((*reg_num) * sizeof(char *));

        for (i = 0; i < *reg_num; i++)
        {
            g_pVBoxFuncs->pfnUtf16ToUtf8(reg_name[i], (*reg_name_out)+i);
            g_pVBoxFuncs->pfnUtf16ToUtf8(reg_value[i], (*reg_value_out)+i);
        }

        for (i = 0; i < *reg_num; ++i)
        {
            g_pVBoxFuncs->pfnComUnallocString(reg_name[i]);
            g_pVBoxFuncs->pfnComUnallocString(reg_value[i]);
        }
        g_pVBoxFuncs->pfnArrayOutFree(reg_name);
        g_pVBoxFuncs->pfnArrayOutFree(reg_value);
    }
    else
    {
        print_error("get_registers_dbgapi", "IMachineDebugger_GetRegisters", rc);
        return DBGRET_EGENERAL;
    }

    return DBGRET_SUCCESS;
}

void free_get_registers_array_dbgapi(char** reg_name_out, char** reg_value_out, ULONG reg_num)
{
    for (int i = 0; i < reg_num; i++)
    {
        g_pVBoxFuncs->pfnUtf8Free(*(reg_name_out+i));
        g_pVBoxFuncs->pfnUtf8Free(*(reg_value_out+i));
    }
    if (reg_name_out)
        free(reg_name_out);
    if (reg_value_out)
        free(reg_value_out);
}


DBGRET set_register_dbgapi(IMachineDebugger* debugger, uint32_t cpuid, char* reg_name, char* reg_value)
{
    BSTR set_reg_name;
    BSTR set_reg_value;
    g_pVBoxFuncs->pfnUtf8ToUtf16(reg_name, &set_reg_name);
    g_pVBoxFuncs->pfnUtf8ToUtf16(reg_value, &set_reg_value);
    HRESULT rc = IMachineDebugger_SetRegister(debugger, cpuid, set_reg_name, set_reg_value);
    g_pVBoxFuncs->pfnUtf16Free(set_reg_name);
    g_pVBoxFuncs->pfnUtf16Free(set_reg_value);
    if (FAILED(rc))
    {
        print_error("set_register_dbgapi", "IMachineDebugger_SetRegister", rc);
        return DBGRET_EGENERAL;
    }

    return DBGRET_SUCCESS;
}


DBGRET cmdctl_dbgapi(IMachineDebugger* debugger, uint64_t cmd)
{
    return cmdctl_dbgapi_out(debugger, cmd, 0, NULL, NULL, 0);
}

DBGRET cmdctl_dbgapi_out(IMachineDebugger* debugger, uint64_t cmd, uint32_t size, uint32_t* out_size, uint8_t** data, uint8_t has_data)
{
    SAFEARRAY* mem_arr = g_pVBoxFuncs->pfnSafeArrayOutParamAlloc();
    HRESULT rc = IMachineDebugger_ReadPhysicalMemory(debugger, cmd, size, ComSafeArrayAsOutTypeParam(mem_arr, uint8_t));
    if (SUCCEEDED(rc))
    {
        ULONG arr_sz = 0;
        if (has_data)
        {
            g_pVBoxFuncs->pfnSafeArrayCopyOutParamHelper((void **)data, &arr_sz, VT_UI1, mem_arr);
            *out_size = arr_sz / sizeof((*data)[0]);
        }

        g_pVBoxFuncs->pfnSafeArrayDestroy(mem_arr);

    }
    else
    {
        print_error("cmdctl_dbgapi_out", "IMachineDebugger_ReadPhysicalMemory", rc);
        g_pVBoxFuncs->pfnSafeArrayDestroy(mem_arr);
        return DBGRET_EGENERAL;
    }
    return DBGRET_SUCCESS;
}

DBGRET cmdctl_dbgapi_in(IMachineDebugger* debugger, uint64_t cmd, uint32_t size, uint8_t* data)
{
    SAFEARRAY* mem_arr = NULL;

    mem_arr = g_pVBoxFuncs->pfnSafeArrayCreateVector(VT_UI1, 0, size);
    g_pVBoxFuncs->pfnSafeArrayCopyInParamHelper(mem_arr, data, size);
    HRESULT rc = IMachineDebugger_WritePhysicalMemory(debugger, cmd, size, ComSafeArrayAsInParam(mem_arr));
    g_pVBoxFuncs->pfnSafeArrayDestroy(mem_arr);
    if (FAILED(rc))
    {
        print_error("cmdctl_dbgapi_in", "IMachineDebugger_WritePhysicalMemory", rc);
        return DBGRET_EGENERAL;
    }

    return DBGRET_SUCCESS;
}

DBGRET cmdctl_dbgapi_duplex(IMachineDebugger* debugger, uint64_t cmd, uint32_t in_size, uint8_t* in_data, uint32_t out_exp_size, uint32_t* out_ect_size, uint8_t** out_data)
{
    SAFEARRAY* in_sarr = NULL;
    SAFEARRAY* out_sarr = NULL;
    HRESULT rc;

    in_sarr = g_pVBoxFuncs->pfnSafeArrayCreateVector(VT_UI1, 0, in_size);
    g_pVBoxFuncs->pfnSafeArrayCopyInParamHelper(in_sarr, in_data, in_size);
    rc = IMachineDebugger_WritePhysicalMemory(debugger, cmd, in_size, ComSafeArrayAsInParam(in_sarr));
    g_pVBoxFuncs->pfnSafeArrayDestroy(in_sarr);
    if (FAILED(rc))
    {
        print_error("cmdctl_dbgapi_duplex", "IMachineDebugger_WritePhysicalMemory", rc);
        return DBGRET_EGENERAL;
    }

    out_sarr = g_pVBoxFuncs->pfnSafeArrayOutParamAlloc();
    rc = IMachineDebugger_ReadPhysicalMemory(debugger, DUPLEX_CMD, out_exp_size, ComSafeArrayAsOutTypeParam(out_sarr, uint8_t));
    if (SUCCEEDED(rc))
    {
        ULONG arr_sz = 0;
        g_pVBoxFuncs->pfnSafeArrayCopyOutParamHelper((void **)out_data, &arr_sz, VT_UI1, out_sarr);
        *out_ect_size = arr_sz / sizeof((*out_data)[0]);

        g_pVBoxFuncs->pfnSafeArrayDestroy(out_sarr);

    }
    else
    {
        print_error("cmdctl_dbgapi_duplex", "IMachineDebugger_ReadPhysicalMemory", rc);
        g_pVBoxFuncs->pfnSafeArrayDestroy(out_sarr);
        return DBGRET_EGENERAL;
    }

    return DBGRET_SUCCESS;
}


DBGRET read_physical_memory_dbgapi(IMachineDebugger* debugger, uint64_t address, uint32_t size, uint32_t* out_size, uint8_t** data)
{
    SAFEARRAY* mem_arr = g_pVBoxFuncs->pfnSafeArrayOutParamAlloc();
    HRESULT rc = IMachineDebugger_ReadPhysicalMemory(debugger, address, size, ComSafeArrayAsOutTypeParam(mem_arr, uint8_t));
    if (SUCCEEDED(rc))
    {
        ULONG arr_sz = 0;
        g_pVBoxFuncs->pfnSafeArrayCopyOutParamHelper((void **)data, &arr_sz, VT_UI1, mem_arr);
        g_pVBoxFuncs->pfnSafeArrayDestroy(mem_arr);
        *out_size = arr_sz / sizeof((*data)[0]);
    }
    else
    {
        print_error("read_physical_memory_dbgapi", "IMachineDebugger_ReadPhysicalMemory", rc);
        g_pVBoxFuncs->pfnSafeArrayDestroy(mem_arr);
        return DBGRET_EGENERAL;
    }
    return DBGRET_SUCCESS;
}

void free_read_memory_array_dbgapi(uint8_t* data)
{
    if (data)
        g_pVBoxFuncs->pfnArrayOutFree(data);
}

DBGRET write_physical_memory_dbgapi(IMachineDebugger* debugger, uint64_t address, uint32_t size, uint8_t* data)
{
    SAFEARRAY* mem_arr = NULL;

    mem_arr = g_pVBoxFuncs->pfnSafeArrayCreateVector(VT_UI1, 0, size);
    g_pVBoxFuncs->pfnSafeArrayCopyInParamHelper(mem_arr, data, size);
    HRESULT rc = IMachineDebugger_WritePhysicalMemory(debugger, address, size, ComSafeArrayAsInParam(mem_arr));
    g_pVBoxFuncs->pfnSafeArrayDestroy(mem_arr);
    if (FAILED(rc))
    {
        print_error("write_physical_memory_dbgapi", "IMachineDebugger_WritePhysicalMemory", rc);
        return DBGRET_EGENERAL;
    }

    return DBGRET_SUCCESS;
}



DBGRET read_virtual_memory_dbgapi(IMachineDebugger* debugger, uint32_t cpuid, uint64_t address, uint32_t size, uint32_t* out_size, uint8_t** data)
{
    SAFEARRAY* mem_arr = g_pVBoxFuncs->pfnSafeArrayOutParamAlloc();
    HRESULT rc = IMachineDebugger_ReadVirtualMemory(debugger, cpuid, address, size, ComSafeArrayAsOutTypeParam(mem_arr, uint8_t));
    if (SUCCEEDED(rc))
    {
        ULONG arr_sz = 0;
        g_pVBoxFuncs->pfnSafeArrayCopyOutParamHelper((void **)data, &arr_sz, VT_UI1, mem_arr);
        g_pVBoxFuncs->pfnSafeArrayDestroy(mem_arr);
        *out_size = arr_sz / sizeof((*data)[0]);
    }
    else
    {
        print_error("read_virtual_memory_dbgapi", "IMachineDebugger_ReadVirtualMemory", rc);
        g_pVBoxFuncs->pfnSafeArrayDestroy(mem_arr);
        return DBGRET_EGENERAL;
    }
    return DBGRET_SUCCESS;
}

DBGRET write_virtual_memory_dbgapi(IMachineDebugger* debugger, uint32_t cpuid, uint64_t address, uint32_t size, uint8_t* data)
{
    SAFEARRAY* mem_arr = NULL;

    mem_arr = g_pVBoxFuncs->pfnSafeArrayCreateVector(VT_UI1, 0, size);
    g_pVBoxFuncs->pfnSafeArrayCopyInParamHelper(mem_arr, data, size);
    HRESULT rc = IMachineDebugger_WriteVirtualMemory(debugger, cpuid, address, size, ComSafeArrayAsInParam(mem_arr));
    g_pVBoxFuncs->pfnSafeArrayDestroy(mem_arr);
    if (FAILED(rc))
    {
        print_error("write_virtual_memory_dbgapi", "IMachineDebugger_WriteVirtualMemory", rc);
        return DBGRET_EGENERAL;
    }

    return DBGRET_SUCCESS;
}

DBGRET wait4event_dbgapi(IMachineDebugger* debugger)
{
    DBGRET ret;
    uint32_t out_sz;
    uint32_t cpu_count;
    uint8_t *out_data;
    uint64_t event_type;

    ret = cmdctl_dbgapi_out(debugger, WAIT4EVENT_CMD, sizeof(event_type), &out_sz, &out_data, 1);
    if (!ret)
    {
        if (out_sz == sizeof(event_type))
        {
            event_type = *(uint64_t *)out_data;

            switch (event_type)
            {
            case 0x1:
                ret = get_cpu_count_dbgapi(g_machine, &cpu_count);
                if (ret)
                {
                    cpu_count = 1;
                }

                for (uint32_t i = 0; i < cpu_count; i++)
                {
                    ret = set_register_dbgapi(debugger, i, "eflags.rf", "1");
                    if (ret)
                    {
                        print_message(DBGSHELL_MSGWARN, "wait4event_dbgapi", "Failed to set eflags.rf to 1 on CPU %u", i);
                    }
                }

                break;
            case 0x5:
            case 0x6:
                ret = get_cpu_count_dbgapi(g_machine, &cpu_count);
                if (ret)
                {
                    cpu_count = 1;
                }

                for (uint32_t i = 0; i < cpu_count; i++)
                {
                    ret = set_register_dbgapi(debugger, i, "eflags.tf", "0");
                    if (ret)
                    {
                        print_message(DBGSHELL_MSGWARN, "wait4event_dbgapi", "Failed to set eflags.tf to 0 on CPU %u", i);
                    }
                }

                break;
            default:
                break;
            }
        }

        free_read_memory_array_dbgapi(out_data);
    }

    return ret;
}

DBGRET add_breakpoint_dbgapi(IMachineDebugger* debugger, uint64_t is_hard_brkp, uint64_t hard_type, uint64_t cpu_id, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable, uint64_t access_sz, uint32_t* ibp)
{
    uint64_t params[] = {is_hard_brkp, hard_type, cpu_id, address, hit_trigger, has_hit_disable, hit_disable, access_sz};
    uint32_t out_sz, ibp_tmp;
    uint8_t* out_data;
    DBGRET ret;

    ret = cmdctl_dbgapi_duplex(debugger, ADD_BRKP_CMD, sizeof(params), (uint8_t *)params, sizeof(uint32_t), &out_sz, &out_data);
    if (!ret)
    {
        ibp_tmp = *(uint32_t *)out_data;
        free_read_memory_array_dbgapi(out_data);
        if (ibp)
        {
            *ibp = ibp_tmp;
        }

        ret = bp_add(ibp_tmp, is_hard_brkp, hard_type, cpu_id, address, hit_trigger, has_hit_disable, hit_disable, access_sz);
        if (ret)
        {
            del_breakpoint_dbgapi(debugger, ibp_tmp);
        }
    }

    return ret;
}

DBGRET add_sw_bp_dbgapi(IMachineDebugger* debugger, uint32_t* ibp, uint32_t cpu_id, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable)
{
    return add_breakpoint_dbgapi(debugger, 0, 0, cpu_id, address, hit_trigger, has_hit_disable, hit_disable, 0, ibp);
}

DBGRET add_hw_bp_dbgapi(IMachineDebugger* debugger, uint32_t* ibp, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable)
{
    return add_breakpoint_dbgapi(debugger, 1, 0, 0, address, hit_trigger, has_hit_disable, hit_disable, 1, ibp);
}

DBGRET add_wo_wp_dbgapi(IMachineDebugger* debugger, uint32_t* ibp, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable, uint64_t access_sz)
{
    return add_breakpoint_dbgapi(debugger, 1, 2, 0, address, hit_trigger, has_hit_disable, hit_disable, access_sz, ibp);
}

DBGRET add_rw_wp_dbgapi(IMachineDebugger* debugger, uint32_t* ibp, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable, uint64_t access_sz)
{
    return add_breakpoint_dbgapi(debugger, 1, 1, 0, address, hit_trigger, has_hit_disable, hit_disable, access_sz, ibp);
}

DBGRET del_breakpoint_dbgapi(IMachineDebugger* debugger, uint32_t ibp)
{
    DBGRET ret;
    ret = cmdctl_dbgapi_in(debugger, DEL_BRKP_CMD, sizeof(ibp), (uint8_t *)&ibp);
    bp_del(ibp);

    return ret;
}

DBGRET step_over_dbgapi(IMachineDebugger* debugger, uint32_t cpu_id)
{
    DBGRET ret;
    ret = cmdctl_dbgapi_in(debugger, STEP_OVER_CMD, sizeof(cpu_id), (uint8_t *)&cpu_id);

    return ret;
}

DBGRET step_into_dbgapi(IMachineDebugger* debugger, uint32_t cpu_id)
{
    DBGRET ret;
    ret = cmdctl_dbgapi_in(debugger, STEP_INTO_CMD, sizeof(cpu_id), (uint8_t *)&cpu_id);

    return ret;
}

DBGRET v2pa_dbgapi(IMachineDebugger* debugger, uint32_t cpu_id, uint64_t vir_addr, uint64_t* phy_addr)
{
    uint32_t out_sz;
    uint8_t* out_data;
    DBGRET ret;
    uint64_t params[] = {cpu_id, vir_addr};

    ret = cmdctl_dbgapi_duplex(debugger, VPA_CVT_CMD, sizeof(params), (uint8_t *)params, sizeof(uint64_t), &out_sz, &out_data);
    if (!ret)
    {
        *phy_addr = *(uint64_t *)out_data;
        free_read_memory_array_dbgapi(out_data);
    }

    return ret;
}

