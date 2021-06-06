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

#include "dbgbreakpoint.h"

pbp_node bp_head;

int64_t bp_get_ibp(uint64_t is_hard_brkp, uint64_t hard_type, uint64_t address, uint64_t access_sz)
{
    pbp_node pbp = bp_head;
    for (; pbp; pbp = pbp->next)
    {
        if (is_hard_brkp)
        {
            if (hard_type == 0)
            {
                if (pbp->is_hard_brkp == is_hard_brkp && pbp->hard_type == hard_type &&
                    pbp->address == address)
                    return pbp->ibp;
            }
            else
            {
                if (pbp->is_hard_brkp == is_hard_brkp && pbp->hard_type == hard_type &&
                    pbp->address == address && pbp->access_sz == access_sz)
                    return pbp->ibp;
            }
        }
        else
        {
            if (pbp->is_hard_brkp == is_hard_brkp && pbp->address == address)
                return pbp->ibp;
        }
    }
    return -1;
}

pbp_node bp_get(uint32_t ibp)
{
    /*
     * Enumerate the list.
     */
    pbp_node pbp = bp_head;
    for (; pbp; pbp = pbp->next)
        if (pbp->ibp == ibp)
            return pbp;
    return NULL;
}

DBGRET bp_add(uint32_t ibp, uint64_t is_hard_brkp, uint64_t hard_type, uint64_t cpu_id, uint64_t address, uint64_t hit_trigger, uint64_t has_hit_disable, uint64_t hit_disable, uint64_t access_sz)
{
    /*
     * Check if it already exists.
     */
    pbp_node pbp = bp_get(ibp);
    if (!pbp)
    {
        pbp = (pbp_node)malloc(sizeof(bp_node));
        if (!pbp)
            return DBGRET_EOUTOFMEM;

        pbp->next = bp_head;
        bp_head = pbp;
    }

    /*
     * Add the breakpoint.
     */
    pbp->ibp = ibp;
    pbp->is_hard_brkp = is_hard_brkp;
    pbp->hard_type = hard_type;
    pbp->cpu_id = cpu_id;
    pbp->address = address;
    pbp->hit_trigger = hit_trigger;
    pbp->has_hit_disable = has_hit_disable;
    pbp->hit_disable = hit_disable;
    pbp->access_sz = access_sz;

    return DBGRET_SUCCESS;
}



DBGRET bp_del(uint32_t ibp)
{
    /*
     * Search thru the list, when found unlink and free it.
     */
    pbp_node prev = NULL;
    pbp_node pbp = bp_head;
    for (; pbp; pbp = pbp->next)
    {
        if (pbp->ibp == ibp)
        {
            if (prev)
                prev->next = pbp->next;
            else
                bp_head = pbp->next;
            free(pbp);
            return DBGRET_SUCCESS;
        }
        prev = pbp;
    }

    return DBGRET_EGENERAL;
}





