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

#ifndef SDK_BINDINGS_C_SERVER_DBGAPI
#define SDK_BINDINGS_C_SERVER_DBGAPI

#include "VBoxCAPIGlue.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#ifndef WIN32
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/poll.h>
#endif
#ifdef IPRT_INCLUDED_cdefs_h
# error "not supposed to involve any IPRT or VBox headers here."
#endif

#include "dbgmisc.h"
#include "dbgshell.h"
#include "dbgbreakpoint.h"

#define DUPLEX_CMD (0xbe01UL << 48)
#define WAIT4EVENT_CMD (0xbe02UL << 48)
#define ADD_BRKP_CMD (0xbe03UL << 48)
#define DEL_BRKP_CMD (0xbe04UL << 48)
#define STEP_OVER_CMD (0xbe05UL << 48)
#define STEP_INTO_CMD (0xbe06UL << 48)
#define VPA_CVT_CMD (0xbe07UL << 48)

DBGRET init_dbgapi(ISession* session, IConsole** console, IMachineDebugger** debugger);
DBGRET release_dbgapi(IConsole *console, IMachineDebugger *debugger);
DBGRET get_cpu_count_dbgapi(IMachine* machine, uint32_t* cpu_count);
DBGRET get_singlestep_dbgapi(IMachineDebugger *debugger, uint8_t *sstep);
DBGRET set_singlestep_dbgapi(IMachineDebugger *debugger, uint8_t sstep);
DBGRET get_registers_dbgapi(IMachineDebugger *debugger, uint32_t cpuid, char ***reg_name_out, char ***reg_value_out, ULONG *reg_num);
DBGRET set_register_dbgapi(IMachineDebugger *debugger, uint32_t cpuid, char *reg_name, char *reg_value);
void free_get_registers_array_dbgapi(char **reg_name_out, char **reg_value_out, ULONG reg_num);
DBGRET cmdctl_dbgapi(IMachineDebugger *debugger, uint64_t cmd);
DBGRET cmdctl_dbgapi_out(IMachineDebugger* debugger, uint64_t cmd, uint32_t size, uint32_t* out_size, uint8_t** data, uint8_t has_data);
DBGRET cmdctl_dbgapi_in(IMachineDebugger *debugger, uint64_t cmd, uint32_t size, uint8_t *data);
DBGRET cmdctl_dbgapi_duplex(IMachineDebugger *debugger, uint64_t cmd, uint32_t in_size, uint8_t *in_data, uint32_t out_exp_size, uint32_t *out_ect_size, uint8_t **out_data);
DBGRET read_physical_memory_dbgapi(IMachineDebugger *debugger, uint64_t address, uint32_t size, uint32_t *out_size, uint8_t **data);
DBGRET write_physical_memory_dbgapi(IMachineDebugger *debugger, uint64_t address, uint32_t size, uint8_t *data);
DBGRET read_virtual_memory_dbgapi(IMachineDebugger *debugger, uint32_t cpuid, uint64_t address, uint32_t size, uint32_t *out_size, uint8_t **data);
DBGRET write_virtual_memory_dbgapi(IMachineDebugger *debugger, uint32_t cpuid, uint64_t address, uint32_t size, uint8_t *data);
void free_read_memory_array_dbgapi(uint8_t *data);
DBGRET wait4event_dbgapi(IMachineDebugger *debugger);
DBGRET add_breakpoint_dbgapi(IMachineDebugger *debugger, uint64_t is_hard_brkp, uint64_t hard_type, uint64_t cpu_id, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable, uint64_t access_sz, uint32_t *ibp);
DBGRET add_sw_bp_dbgapi(IMachineDebugger *debugger, uint32_t *ibp, uint32_t cpu_id, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable);
DBGRET add_hw_bp_dbgapi(IMachineDebugger *debugger, uint32_t *ibp, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable);
DBGRET add_wo_wp_dbgapi(IMachineDebugger *debugger, uint32_t *ibp, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable, uint64_t access_sz);
DBGRET add_rw_wp_dbgapi(IMachineDebugger *debugger, uint32_t *ibp, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable, uint64_t access_sz);
DBGRET del_breakpoint_dbgapi(IMachineDebugger *debugger, uint32_t ibp);
DBGRET step_over_dbgapi(IMachineDebugger *debugger, uint32_t cpu_id);
DBGRET step_into_dbgapi(IMachineDebugger *debugger, uint32_t cpu_id);
DBGRET v2pa_dbgapi(IMachineDebugger *debugger, uint32_t cpu_id, uint64_t vir_addr, uint64_t *phy_addr);

#endif /* SDK_BINDINGS_C_SERVER_DBGAPI */
