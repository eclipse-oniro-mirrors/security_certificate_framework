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

#include "cf_adapter_cert_openssl.h"
#include "cf_adapter_extension_openssl.h"
#include "cf_cert_adapter_ability_define.h"
#include "cf_extension_adapter_ability_define.h"
#include "cf_log.h"
#include "cf_magic.h"

static CfCertAdapterAbilityFunc g_certAdapterFunc = {
    .base.type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_FUNC, CF_OBJ_TYPE_CERT),
    .adapterCreate = CfOpensslCreateCert,
    .adapterDestory = CfOpensslDestoryCert,
    .adapterVerify = CfOpensslVerifyCert,
    .adapterGetItem = CfOpensslGetCertItem,
};

static CfExtensionAdapterAbilityFunc g_extensionAdapterFunc = {
    .base.type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_FUNC, CF_OBJ_TYPE_EXTENSION),
    .adapterCreate = CfOpensslCreateExtension,
    .adapterDestory = CfOpensslDestoryExtension,
    .adapterGetOids = CfOpensslGetOids,
    .adapterGetEntry = CfOpensslGetEntry,
    .adapterGetItem = CfOpensslGetExtensionItem,
    .adapterCheckCA = CfOpensslCheckCA,
    .adapterHasUnsupportedCriticalExtension = CfOpensslHasUnsupportedCriticalExtension,
};

__attribute__((constructor)) static void LoadAdapterAbility(void)
{
    CF_LOG_I("enter load adapter ability");
    (void)RegisterAbility(CF_ABILITY(CF_ABILITY_TYPE_ADAPTER, CF_OBJ_TYPE_CERT), &g_certAdapterFunc.base);
    (void)RegisterAbility(CF_ABILITY(CF_ABILITY_TYPE_ADAPTER, CF_OBJ_TYPE_EXTENSION), &g_extensionAdapterFunc.base);
}

