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

#ifndef CF_ABILITY_H
#define CF_ABILITY_H

#include "cf_type.h"

typedef enum {
    CF_ABILITY_TYPE_ADAPTER = 1,
    CF_ABILITY_TYPE_OBJECT = 2,
} CfAbilityType;

#define CF_ABILITY_MAX_SIZE 128
#define CF_ABILITY_SHIFT 24
#define CF_ABILITY(abilityType, objType) (((abilityType) << CF_ABILITY_SHIFT) | (objType))

typedef struct {
    uint32_t id;
    CfBase *func;
} CfAbility;

#ifdef __cplusplus
extern "C" {
#endif

int32_t RegisterAbility(uint32_t id, CfBase *func);

CfBase *GetAbility(uint32_t id);

#ifdef __cplusplus
}
#endif

#endif /* CF_ABILITY_H */
