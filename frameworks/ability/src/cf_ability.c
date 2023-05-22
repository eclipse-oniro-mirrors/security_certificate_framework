/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cf_ability.h"

#include "cf_log.h"
#include "cf_result.h"

static CfAbility g_abilityList[CF_ABILITY_MAX_SIZE] = {{0}};

int32_t RegisterAbility(uint32_t id, CfBase *func)
{
    for (uint32_t i = 0; i < CF_ABILITY_MAX_SIZE; ++i) {
        if (g_abilityList[i].id == id) {
            return CF_NOT_SUPPORT;
        } else if (g_abilityList[i].id != 0) {
            continue;
        }

        g_abilityList[i].id = id;
        g_abilityList[i].func = func;
        return CF_SUCCESS;
    }
    CF_LOG_E("register failed: exceed max number of abilities, id = %u", id);
    return CF_NOT_SUPPORT;
}

CfBase *GetAbility(uint32_t id)
{
    for (uint32_t i = 0; i < CF_ABILITY_MAX_SIZE; ++i) {
        if (g_abilityList[i].id == id) {
            return g_abilityList[i].func;
        }
    }
    return NULL;
}

