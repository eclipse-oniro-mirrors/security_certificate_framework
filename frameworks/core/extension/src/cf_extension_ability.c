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
#include "cf_magic.h"
#include "cf_object_ability_define.h"
#include "cf_object_extension.h"

static CfObjectAbilityFunc g_extensionObjectFunc = {
    .base.type = CF_MAGIC(CF_MAGIC_TYPE_OBJ_FUNC, CF_OBJ_TYPE_EXTENSION),
    .create = CfExtensionCreate,
    .destroy = CfExtensionDestroy,
    .check = CfExtensionCheck,
    .get = CfExtensionGet,
};

__attribute__((constructor)) static void LoadExtensionOjbectAbility(void)
{
    CF_LOG_I("enter load extension object ability");
    (void)RegisterAbility(CF_ABILITY(CF_ABILITY_TYPE_OBJECT, CF_OBJ_TYPE_EXTENSION), &g_extensionObjectFunc.base);
}
