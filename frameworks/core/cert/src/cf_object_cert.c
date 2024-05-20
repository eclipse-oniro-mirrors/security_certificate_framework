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

#include "cf_object_cert.h"

#include "securec.h"

#include "cf_ability.h"
#include "cf_log.h"
#include "cf_magic.h"
#include "cf_memory.h"
#include "cf_param.h"
#include "cf_param_parse.h"
#include "cf_result.h"

#include "cf_cert_adapter_ability_define.h"

typedef struct {
    CfBase base;
    CfCertAdapterAbilityFunc func;
    CfBase *adapterRes;
} CfCertObjStruct;

int32_t CfCertCreate(const CfEncodingBlob *in, CfBase **obj)
{
    if ((in == NULL) || (obj == NULL)) {
        CF_LOG_E("param null");
        return CF_NULL_POINTER;
    }

    CfCertAdapterAbilityFunc *func = (CfCertAdapterAbilityFunc *)GetAbility(CF_ABILITY(CF_ABILITY_TYPE_ADAPTER,
        CF_OBJ_TYPE_CERT));
    if ((func == NULL) || (func->base.type != CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_FUNC, CF_OBJ_TYPE_CERT))) {
        CF_LOG_E("invalid func type");
        return CF_INVALID_PARAMS;
    }

    CfCertObjStruct *tmp = CfMalloc(sizeof(CfCertObjStruct), 0);
    if (tmp == NULL) {
        CF_LOG_E("malloc cert obj failed");
        return CF_ERR_MALLOC;
    }
    tmp->base.type = CF_MAGIC(CF_MAGIC_TYPE_OBJ_RESOURCE, CF_OBJ_TYPE_CERT);

    int32_t ret = func->adapterCreate(in, &tmp->adapterRes);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("cert adapter create failed");
        CfFree(tmp);
        return ret;
    }
    (void)memcpy_s(&tmp->func, sizeof(CfCertAdapterAbilityFunc), func, sizeof(CfCertAdapterAbilityFunc));

    *obj = &(tmp->base);
    return CF_SUCCESS;
}

static int32_t CfCertGetItem(const CfCertObjStruct *obj, const CfParamSet *in, CfParamSet **out)
{
    CfParam *tmpParam = NULL;
    int32_t ret = CfGetParam(in, CF_TAG_PARAM0_INT32, &tmpParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get item id failed, ret = %d", ret);
        return ret;
    }

    CF_LOG_I("cert get type = 0x%x", tmpParam->int32Param);
    CfBlob itemValue = { 0, NULL };
    ret = obj->func.adapterGetItem(obj->adapterRes, (CfItemId)tmpParam->int32Param, &itemValue);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("adapter get item failed, ret = %d", ret);
        return ret;
    }

    CfParam params[] = {
        { .tag = CF_TAG_RESULT_TYPE, .int32Param = CF_TAG_TYPE_BYTES },
        { .tag = CF_TAG_RESULT_BYTES, .blob = itemValue },
    };
    ret = CfConstructParamSetOut(params, sizeof(params) / sizeof(CfParam), out);
    CfFree(itemValue.data);
    return ret;
}

int32_t CfCertGet(const CfBase *obj, const CfParamSet *in, CfParamSet **out)
{
    if ((obj == NULL) || (in == NULL) || (out == NULL)) {
        CF_LOG_E("cfcertget params is null");
        return CF_NULL_POINTER;
    }

    CfCertObjStruct *tmp = (CfCertObjStruct *)obj;
    if (tmp->base.type != CF_MAGIC(CF_MAGIC_TYPE_OBJ_RESOURCE, CF_OBJ_TYPE_CERT)) {
        CF_LOG_E("invalid resource type");
        return CF_INVALID_PARAMS;
    }

    CfParam *tmpParam = NULL;
    int32_t ret = CfGetParam(in, CF_TAG_GET_TYPE, &tmpParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get param item type failed, ret = %d", ret);
        return ret;
    }

    switch (tmpParam->int32Param) {
        case CF_GET_TYPE_CERT_ITEM:
            return CfCertGetItem(tmp, in, out);
        default:
            CF_LOG_E("cert get type invalid, type = %d", tmpParam->int32Param);
            return CF_NOT_SUPPORT;
    }
}

int32_t CfCertCheck(const CfBase *obj, const CfParamSet *in, CfParamSet **out)
{
    if ((obj == NULL) || (in == NULL) || (out == NULL)) {
        CF_LOG_E("cfcertcheck params is null");
        return CF_NULL_POINTER;
    }

    CfCertObjStruct *tmp = (CfCertObjStruct *)obj;
    if (tmp->base.type != CF_MAGIC(CF_MAGIC_TYPE_OBJ_RESOURCE, CF_OBJ_TYPE_CERT)) {
        CF_LOG_E("invalid resource type");
        return CF_INVALID_PARAMS;
    }

    return CF_SUCCESS; /* reserve check function */
}

void CfCertDestroy(CfBase **obj)
{
    if ((obj == NULL) || (*obj == NULL)) {
        return;
    }

    CfCertObjStruct *tmp = (CfCertObjStruct *)*obj;
    if (tmp->base.type != CF_MAGIC(CF_MAGIC_TYPE_OBJ_RESOURCE, CF_OBJ_TYPE_CERT)) {
        /* only cert objects can be destroyed */
        CF_LOG_E("invalid resource type");
        return;
    }

    tmp->func.adapterDestory(&tmp->adapterRes);
    CfFree(tmp);
    *obj = NULL;
    return;
}

