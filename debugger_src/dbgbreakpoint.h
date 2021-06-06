#ifndef SDK_BINDINGS_C_SERVER_DBGBREAKPOINT
#define SDK_BINDINGS_C_SERVER_DBGBREAKPOINT

#include "dbgmisc.h"
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

typedef struct bp_node
{
    struct bp_node* next;
    uint32_t ibp;
    uint64_t is_hard_brkp;
    uint64_t hard_type;
    uint64_t cpu_id;
    uint64_t address;
    uint64_t hit_trigger;
    uint64_t has_hit_disable;
    uint64_t hit_disable;
    uint64_t access_sz;
} bp_node, *pbp_node;

extern pbp_node bp_head;

int64_t bp_get_ibp(uint64_t is_hard_brkp, uint64_t hard_type, uint64_t address, uint64_t access_sz);
pbp_node bp_get(uint32_t ibp);
DBGRET bp_add(uint32_t ibp, uint64_t is_hard_brkp, uint64_t hard_type, uint64_t cpu_id, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable, uint64_t access_sz);
DBGRET bp_del(uint32_t ibp);

#endif /* SDK_BINDINGS_C_SERVER_DBGBREAKPOINT */
