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

#include "cf_object_extension.h"

#include "securec.h"

#include "cf_ability.h"
#include "cf_log.h"
#include "cf_magic.h"
#include "cf_memory.h"
#include "cf_param.h"
#include "cf_param_parse.h"
#include "cf_result.h"

#include "cf_extension_adapter_ability_define.h"

typedef struct {
    CfBase base;
    CfExtensionAdapterAbilityFunc func;
    CfBase *adapterRes;
} CfExtensionObjStruct;

int32_t CfExtensionCreate(const CfEncodingBlob *in, CfBase **obj)
{
    if ((in == NULL) || (obj == NULL)) {
        CF_LOG_E("param null");
        return CF_NULL_POINTER;
    }

    CfExtensionAdapterAbilityFunc *func = (CfExtensionAdapterAbilityFunc *)GetAbility(
        CF_ABILITY(CF_ABILITY_TYPE_ADAPTER, CF_OBJ_TYPE_EXTENSION));
    if ((func == NULL) || (func->base.type != CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_FUNC, CF_OBJ_TYPE_EXTENSION))) {
        CF_LOG_E("invalid func type");
        return CF_INVALID_PARAMS;
    }

    CfExtensionObjStruct *tmp = CfMalloc(sizeof(CfExtensionObjStruct), 0);
    if (tmp == NULL) {
        CF_LOG_E("malloc cert obj failed");
        return CF_ERR_MALLOC;
    }

    tmp->base.type = CF_MAGIC(CF_MAGIC_TYPE_OBJ_RESOURCE, CF_OBJ_TYPE_EXTENSION);
    int32_t ret = func->adapterCreate(in, &tmp->adapterRes);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("cert adapter create failed");
        CfFree(tmp);
        return ret;
    }
    (void)memcpy_s(&tmp->func, sizeof(CfExtensionAdapterAbilityFunc), func, sizeof(CfExtensionAdapterAbilityFunc));

    *obj = &(tmp->base);
    return CF_SUCCESS;
}

static int32_t CfExtGetItem(const CfExtensionObjStruct *obj, const CfParamSet *in, CfParamSet **out)
{
    CfParam *tmpParam = NULL;
    int32_t ret = CfGetParam(in, CF_TAG_PARAM0_INT32, &tmpParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("ext get item failed, ret = %d", ret);
        return ret;
    }

    CfBlob itemRes = { 0, NULL };
    ret = obj->func.adapterGetItem(obj->adapterRes, (CfItemId)tmpParam->int32Param, &itemRes);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("ext adapter get item failed, ret = %d", ret);
        return ret;
    }

    CfParam params[] = {
        { .tag = CF_TAG_RESULT_TYPE, .int32Param = CF_TAG_TYPE_BYTES },
        { .tag = CF_TAG_RESULT_BYTES, .blob = itemRes },
    };
    ret = CfConstructParamSetOut(params, sizeof(params) / sizeof(CfParam), out);
    CfFree(itemRes.data);
    return ret;
}

static int32_t CfExtGetOids(const CfExtensionObjStruct *obj, const CfParamSet *in, CfParamSet **out)
{
    CfParam *oidTypeParam = NULL;
    int32_t ret = CfGetParam(in, CF_TAG_PARAM0_INT32, &oidTypeParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get oid type failed, ret = %d", ret);
        return ret;
    }

    CfBlobArray oids = { NULL, 0 };
    ret = obj->func.adapterGetOids(obj->adapterRes, (CfExtensionOidType)oidTypeParam->int32Param, &oids);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("adapter get oids failed, ret = %d", ret);
        return ret;
    }

    ret = CfConstructArrayParamSetOut(&oids, out);
    FreeCfBlobArray(oids.data, oids.count);
    return ret;
}

static int32_t CfExtGetEntry(const CfExtensionObjStruct *obj, const CfParamSet *in, CfParamSet **out)
{
    CfParam *entryTypeParam = NULL;
    int32_t ret = CfGetParam(in, CF_TAG_PARAM0_INT32, &entryTypeParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get entry type failed, ret = %d", ret);
        return ret;
    }

    CfParam *oidParam = NULL;
    ret = CfGetParam(in, CF_TAG_PARAM1_BUFFER, &oidParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get oid failed, ret = %d", ret);
        return ret;
    }

    CfBlob entryValue = { 0, NULL };
    ret = obj->func.adapterGetEntry(obj->adapterRes, (CfExtensionEntryType)entryTypeParam->int32Param,
        &oidParam->blob, &entryValue);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("adapter get entry failed, ret = %d", ret);
        return ret;
    }

    CfParam params[] = {
        { .tag = CF_TAG_RESULT_TYPE, .int32Param = CF_TAG_TYPE_BYTES },
        { .tag = CF_TAG_RESULT_BYTES, .blob = entryValue },
    };
    ret = CfConstructParamSetOut(params, sizeof(params) / sizeof(CfParam), out);
    CfFree(entryValue.data);
    return ret;
}

int32_t CfExtensionGet(const CfBase *obj, const CfParamSet *in, CfParamSet **out)
{
    if ((obj == NULL) || (in == NULL) || (out == NULL)) {
        CF_LOG_E("cfextensionget params is null");
        return CF_NULL_POINTER;
    }

    CfExtensionObjStruct *tmp = (CfExtensionObjStruct *)obj;
    if (tmp->base.type != CF_MAGIC(CF_MAGIC_TYPE_OBJ_RESOURCE, CF_OBJ_TYPE_EXTENSION)) {
        CF_LOG_E("invalid resource type");
        return CF_INVALID_PARAMS;
    }

    CfParam *tmpParam = NULL;
    int32_t ret = CfGetParam(in, CF_TAG_GET_TYPE, &tmpParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get type failed, ret = %d", ret);
        return ret;
    }

    switch (tmpParam->int32Param) {
        case CF_GET_TYPE_EXT_ITEM:
            return CfExtGetItem(tmp, in, out);
        case CF_GET_TYPE_EXT_OIDS:
            return CfExtGetOids(tmp, in, out);
        case CF_GET_TYPE_EXT_ENTRY:
            return CfExtGetEntry(tmp, in, out);
        default:
            CF_LOG_E("extension get type invalid, type = %d", tmpParam->int32Param);
            return CF_NOT_SUPPORT;
    }
}

int32_t CfExtensionCheck(const CfBase *obj, const CfParamSet *in, CfParamSet **out)
{
    if ((obj == NULL) || (in == NULL) || (out == NULL)) {
        CF_LOG_E("cfextensioncheck params is null");
        return CF_NULL_POINTER;
    }

    CfExtensionObjStruct *tmp = (CfExtensionObjStruct *)obj;
    if (tmp->base.type != CF_MAGIC(CF_MAGIC_TYPE_OBJ_RESOURCE, CF_OBJ_TYPE_EXTENSION)) {
        CF_LOG_E("invalid resource type");
        return CF_INVALID_PARAMS;
    }

    CfParam *tmpParam = NULL;
    int32_t ret = CfGetParam(in, CF_TAG_CHECK_TYPE, &tmpParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get check type failed, ret = %d", ret);
        return ret;
    }

    if (tmpParam->int32Param == CF_CHECK_TYPE_EXT_CA) {
        int32_t pathLen;
        ret = tmp->func.adapterCheckCA(tmp->adapterRes, &pathLen);
        if (ret != CF_SUCCESS) {
            CF_LOG_E("adapter check ca failed");
            return ret;
        }

        CfParam params[] = {
            { .tag = CF_TAG_RESULT_TYPE, .int32Param = CF_TAG_TYPE_INT },
            { .tag = CF_TAG_RESULT_INT, .int32Param = pathLen },
        };
        return CfConstructParamSetOut(params, sizeof(params) / sizeof(CfParam), out);
    } else if (tmpParam->int32Param == CF_CHECK_TYPE_EXT_HAS_UN_SUPPORT) {
        bool flag = false;
        ret = tmp->func.adapterHasUnsupportedCriticalExtension(tmp->adapterRes, &flag);
        if (ret != CF_SUCCESS) {
            CF_LOG_E("adapter has unsupported critical extension failed");
            return ret;
        }
        CfParam params[] = {
            { .tag = CF_TAG_RESULT_TYPE, .int32Param = CF_TAG_TYPE_BOOL },
            { .tag = CF_TAG_RESULT_BOOL, .boolParam = flag },
        };
        return CfConstructParamSetOut(params, sizeof(params) / sizeof(CfParam), out);
    }

    CF_LOG_E("extension check type invalid, type = %d", tmpParam->int32Param);
    return CF_NOT_SUPPORT;
}

void CfExtensionDestroy(CfBase **obj)
{
    if ((obj == NULL) || (*obj == NULL)) {
        return;
    }

    CfExtensionObjStruct *tmp = (CfExtensionObjStruct *)*obj;
    if (tmp->base.type != CF_MAGIC(CF_MAGIC_TYPE_OBJ_RESOURCE, CF_OBJ_TYPE_EXTENSION)) {
        /* only extension objects can be destroyed */
        CF_LOG_E("invalid resource type");
        return;
    }

    tmp->func.adapterDestory(&tmp->adapterRes);
    CfFree(tmp);
    *obj = NULL;
    return;
}