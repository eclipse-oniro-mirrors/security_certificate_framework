/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_object.h"

#include "securec.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_param.h"
#include "cf_result.h"

#include "napi_cert_utils.h"
#include "napi_common.h"

using namespace std;

namespace OHOS {
namespace CertFramework {
constexpr size_t MAX_ARGS_COUNT = 5;

constexpr uint32_t NAPI_OUT_TYPE_BLOB = 1;
constexpr uint32_t NAPI_OUT_TYPE_ARRAY = 2;
constexpr uint32_t NAPI_OUT_TYPE_NUMBER = 3;
constexpr uint32_t NAPI_OUT_TYPE_ENCODING_BLOB = 4;
constexpr uint32_t NAPI_OUT_TYPE_BOOL = 5;

constexpr size_t PARAM_INDEX_0 = 0;
constexpr size_t PARAM_INDEX_1 = 1;
constexpr size_t PARAM_INDEX_2 = 2;
constexpr size_t PARAM_INDEX_3 = 3;
constexpr size_t PARAM_INDEX_4 = 4;

constexpr size_t PARAM_COUNT_CERT_GET_ITEM = 1;
constexpr size_t PARAM_COUNT_EXT_GET_OIDS = 1;
constexpr size_t PARAM_COUNT_EXT_GET_ENTRY = 2;
constexpr size_t PARAM_COUNT_EXT_GET_ITEM = 0;
constexpr size_t PARAM_COUNT_EXT_CHECK_CA = 0;
constexpr size_t PARAM_COUNT_EXT_HAS_UN_SUPPORT = 0;

struct CfInputParamsMap {
    int32_t opType;
    int32_t type;
    size_t paramsCnt;
    napi_valuetype expectedType[MAX_ARGS_COUNT];
};

struct CfParamTagMap {
    size_t index;
    napi_valuetype valueType;
    CfTag tag;
};

struct CfResultMap {
    int32_t opType;
    int32_t type;
    CfTag resultType;
    uint32_t outType;
};

const struct CfInputParamsMap INPUT_PARAMS_MAP[] = {
    { OPERATION_TYPE_GET, CF_GET_TYPE_CERT_ITEM, PARAM_COUNT_CERT_GET_ITEM, { napi_number } },
    { OPERATION_TYPE_GET, CF_GET_TYPE_EXT_OIDS, PARAM_COUNT_EXT_GET_OIDS, { napi_number } },
    { OPERATION_TYPE_GET, CF_GET_TYPE_EXT_ENTRY, PARAM_COUNT_EXT_GET_ENTRY, { napi_number, napi_object } },
    { OPERATION_TYPE_GET, CF_GET_TYPE_EXT_ITEM, PARAM_COUNT_EXT_GET_ITEM, { napi_undefined } },
    { OPERATION_TYPE_CHECK, CF_CHECK_TYPE_EXT_CA, PARAM_COUNT_EXT_CHECK_CA, { napi_undefined } },
    { OPERATION_TYPE_CHECK, CF_CHECK_TYPE_EXT_HAS_UN_SUPPORT, PARAM_COUNT_EXT_HAS_UN_SUPPORT, { napi_undefined } },
};

const struct CfParamTagMap TAG_MAP[] = {
    { PARAM_INDEX_0, napi_object, CF_TAG_PARAM0_BUFFER },
    { PARAM_INDEX_1, napi_object, CF_TAG_PARAM1_BUFFER },
    { PARAM_INDEX_2, napi_object, CF_TAG_PARAM2_BUFFER },
    { PARAM_INDEX_3, napi_object, CF_TAG_PARAM3_BUFFER },
    { PARAM_INDEX_4, napi_object, CF_TAG_PARAM4_BUFFER },
    { PARAM_INDEX_0, napi_number, CF_TAG_PARAM0_INT32 },
    { PARAM_INDEX_1, napi_number, CF_TAG_PARAM1_INT32 },
    { PARAM_INDEX_2, napi_number, CF_TAG_PARAM2_INT32 },
    { PARAM_INDEX_3, napi_number, CF_TAG_PARAM3_INT32 },
    { PARAM_INDEX_4, napi_number, CF_TAG_PARAM4_INT32 },
};

const struct CfResultMap RESULT_MAP[] = {
    { OPERATION_TYPE_GET, CF_GET_TYPE_CERT_ITEM, CF_TAG_RESULT_BYTES, NAPI_OUT_TYPE_BLOB },
    { OPERATION_TYPE_GET, CF_GET_TYPE_EXT_OIDS, CF_TAG_RESULT_BYTES, NAPI_OUT_TYPE_ARRAY },
    { OPERATION_TYPE_GET, CF_GET_TYPE_EXT_ENTRY, CF_TAG_RESULT_BYTES, NAPI_OUT_TYPE_BLOB },
    { OPERATION_TYPE_GET, CF_GET_TYPE_EXT_ITEM, CF_TAG_RESULT_BYTES, NAPI_OUT_TYPE_ENCODING_BLOB },
    { OPERATION_TYPE_CHECK, CF_CHECK_TYPE_EXT_CA, CF_TAG_RESULT_INT, NAPI_OUT_TYPE_NUMBER },
    { OPERATION_TYPE_CHECK, CF_CHECK_TYPE_EXT_HAS_UN_SUPPORT, CF_TAG_RESULT_BOOL, NAPI_OUT_TYPE_BOOL },
};

static void FreeParsedParams(vector<CfParam> &params)
{
    CfParam *param = params.data();
    size_t paramCount = params.size();
    if (param == nullptr) {
        return;
    }
    while (paramCount > 0) {
        paramCount--;
        if ((param->tag & CF_TAG_TYPE_MASK) == CF_TAG_TYPE_BYTES) {
            CF_FREE_PTR(param->blob.data);
            param->blob.size = 0;
        }
        ++param;
    }
}

static CfTag GetTagValue(size_t index, napi_valuetype valueType)
{
    uint32_t count = sizeof(TAG_MAP) / sizeof(TAG_MAP[0]);
    for (uint32_t i = 0; i < count; ++i) {
        if ((index == TAG_MAP[i].index) && (valueType == TAG_MAP[i].valueType)) {
            return TAG_MAP[i].tag;
        }
    }
    return CF_TAG_INVALID;
}

static int32_t GetInputObject(napi_env env, napi_value object, size_t index, vector<CfParam> &params)
{
    CfBlob *inBlob = CertGetBlobFromNapiValue(env, object);
    if (inBlob == nullptr) {
        CF_LOG_E("get blob failed");
        return CF_INVALID_PARAMS;
    }

    CfParam param;
    param.tag = GetTagValue(index, napi_object);
    param.blob.data = inBlob->data;
    param.blob.size = inBlob->size;
    params.push_back(param);

    CfFree(inBlob); /* inBlob's data need freed by caller */
    return CF_SUCCESS;
}

static int32_t GetInputNumber(napi_env env, napi_value object, size_t index, vector<CfParam> &params)
{
    CfParam param;
    napi_status status = napi_get_value_int32(env, object, &param.int32Param);
    if (status != napi_ok) {
        CF_LOG_E("can not get int value");
        return CF_INVALID_PARAMS;
    }

    param.tag = GetTagValue(index, napi_number);
    params.push_back(param);
    return CF_SUCCESS;
}

static int32_t GetInputParams(napi_env env, napi_value object, size_t index, vector<CfParam> &params)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, object, &valueType);
    if (status != napi_ok) {
        CF_LOG_E("could not get object type");
        return CF_INVALID_PARAMS;
    }

    if (valueType == napi_object) {
        return GetInputObject(env, object, index, params);
    } else if (valueType == napi_number) {
        return GetInputNumber(env, object, index, params);
    } else {
        return CF_INVALID_PARAMS;
    }
}

static int32_t AddParams(const vector<CfParam> &params, CfParamSet *&paramSet)
{
    const CfParam *param = params.data();
    size_t paramCount = params.size();
    if (param == nullptr) {
        return CF_SUCCESS;
    }

    for (uint32_t i = 0; i < paramCount; ++i) {
        int32_t ret = CfAddParams(paramSet, param, 1);
        if (ret != CF_SUCCESS) {
            CF_LOG_E("add param[%u] failed", i);
            return ret;
        }
        param++;
    }
    return CF_SUCCESS;
}

static int32_t ConstructInParamSet(const vector<CfParam> &params, CfParamSet *&inParamSet)
{
    CfParamSet *tmp = NULL;
    int32_t ret = CfInitParamSet(&tmp);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("init paramSet failed");
        return ret;
    }

    ret = AddParams(params, tmp);
    if (ret != CF_SUCCESS) {
        CfFreeParamSet(&tmp);
        return ret;
    }

    ret = CfBuildParamSet(&tmp);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("build paramSet failed");
        CfFreeParamSet(&tmp);
        return ret;
    }

    inParamSet = tmp;
    return CF_SUCCESS;
}

static void ConstructTypeParams(int32_t opType, int32_t typeValue, vector<CfParam> &params)
{
    CfParam param;
    if (opType == OPERATION_TYPE_GET) {
        param.tag = CF_TAG_GET_TYPE;
        param.int32Param = typeValue;
    } else { /* is check */
        param.tag = CF_TAG_CHECK_TYPE;
        param.int32Param = typeValue;
    }
    params.push_back(param);
}

static int32_t CheckParamsNapiType(napi_env env, napi_value *argv, size_t argc,
    napi_valuetype const *expectedType, size_t expectedCnt)
{
    if (argc != expectedCnt) {
        CF_LOG_E("params count invalid");
        return CF_INVALID_PARAMS;
    }

    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_status status = napi_typeof(env, argv[i], &valueType);
        if (status != napi_ok) {
            CF_LOG_E("could not get object type");
            return CF_INVALID_PARAMS;
        }

        if (valueType != expectedType[i]) {
            CF_LOG_E("input object type invalid");
            return CF_INVALID_PARAMS;
        }
    }

    return CF_SUCCESS;
}

static int32_t CheckInputParams(napi_env env, napi_value *argv, size_t argc, int32_t opType, int32_t typeValue)
{
    for (uint32_t i = 0; i < sizeof(INPUT_PARAMS_MAP) / sizeof(INPUT_PARAMS_MAP[0]); ++i) {
        if ((opType == INPUT_PARAMS_MAP[i].opType) && (typeValue == INPUT_PARAMS_MAP[i].type)) {
            if (CheckParamsNapiType(env, argv, argc, INPUT_PARAMS_MAP[i].expectedType,
                INPUT_PARAMS_MAP[i].paramsCnt) != CF_SUCCESS) {
                return CF_INVALID_PARAMS;
            }
            return CF_SUCCESS;
        }
    }
    return CF_INVALID_PARAMS;
}

static int32_t GetInParamSet(napi_env env, napi_callback_info info, int32_t opType, int32_t typeValue,
    CfParamSet *&inParamSet)
{
    size_t argc = MAX_ARGS_COUNT;
    napi_value argv[MAX_ARGS_COUNT] = { 0 };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    int32_t ret = CheckInputParams(env, argv, argc, opType, typeValue);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("input params invalid");
        return CF_INVALID_PARAMS;
    }

    vector<CfParam> params;
    ConstructTypeParams(opType, typeValue, params);

    for (size_t i = 0; i < argc; ++i) {
        ret = GetInputParams(env, argv[i], i, params);
        if (ret != CF_SUCCESS) {
            FreeParsedParams(params);
            CF_LOG_E("param[%u] invalid", i);
            return ret;
        }
    }

    /* ext get encoded */
    if ((typeValue == CF_GET_TYPE_EXT_ITEM) && (argc == 0)) {
        CfParam paramExtEncoded = { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_ITEM_ENCODED };
        params.push_back(paramExtEncoded);
    }

    ret = ConstructInParamSet(params, inParamSet);
    FreeParsedParams(params);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("construct In paramSet failed");
        return ret;
    }

    return CF_SUCCESS;
}

static int32_t GetResultType(int32_t opType, int32_t typeValue, CfTag &resultType, uint32_t &outType)
{
    for (uint32_t i = 0; i < sizeof(RESULT_MAP) / sizeof(RESULT_MAP[0]); ++i) {
        if ((typeValue == RESULT_MAP[i].type) && (opType == RESULT_MAP[i].opType)) {
            resultType = RESULT_MAP[i].resultType;
            outType = RESULT_MAP[i].outType;
            return CF_SUCCESS;
        }
    }
    return CF_INVALID_PARAMS;
}

static int32_t CheckResultType(const CfParamSet *paramSet, CfTag resultType)
{
    CfParam *resultTypeParam = NULL;
    int32_t ret = CfGetParam(paramSet, CF_TAG_RESULT_TYPE, &resultTypeParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get CF_TAG_RESULT_TYPE failed.");
        return ret;
    }

    if (resultTypeParam->int32Param != (resultType & CF_TAG_TYPE_MASK)) {
        CF_LOG_E("result type[0x%x] is not [0x%x].", resultTypeParam->int32Param, resultType);
        return CF_INVALID_PARAMS;
    }

    return CF_SUCCESS;
}

static napi_value ConvertToNapiValue(napi_env env, int32_t opType, int32_t typeValue, const CfParamSet *paramSet)
{
    CfTag resultType = CF_TAG_INVALID;
    uint32_t outType = 0;
    int32_t ret = GetResultType(opType, typeValue, resultType, outType);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get result type failed.");
        return nullptr;
    }

    ret = CheckResultType(paramSet, resultType);
    if (ret != CF_SUCCESS) {
        return nullptr;
    }

    CfParam *resultParam = NULL;
    ret = CfGetParam(paramSet, resultType, &resultParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("get [0x%x] from param failed.", resultType);
        return nullptr;
    }

    if (outType == NAPI_OUT_TYPE_BLOB) {
        return CertConvertBlobToNapiValue(env, &resultParam->blob);
    } else if (outType == NAPI_OUT_TYPE_ARRAY) {
        CF_LOG_I("blob array");
        return ConvertBlobArrayToNapiValue(env, paramSet);
    } else if (outType == NAPI_OUT_TYPE_NUMBER) {
        napi_value result = nullptr;
        napi_create_int32(env, resultParam->int32Param, &result);
        return result;
    } else if (outType == NAPI_OUT_TYPE_ENCODING_BLOB) {
        CfEncodingBlob encoded = { resultParam->blob.data, resultParam->blob.size, CF_FORMAT_DER };
        return ConvertEncodingBlobToNapiValue(env, &encoded);
    } else if (outType == NAPI_OUT_TYPE_BOOL) {
        napi_value result = nullptr;
        napi_get_boolean(env, resultParam->boolParam, &result);
        return result;
    }

    return nullptr;
}

static int32_t DoOperation(const CfObject *obj, int32_t opType, const CfParamSet *inParamSet,
    CfParamSet **outParamSet)
{
    int32_t ret = CF_INVALID_PARAMS;
    if (opType == OPERATION_TYPE_GET) {
        ret = obj->get(obj, inParamSet, outParamSet);
    } else if (opType == OPERATION_TYPE_CHECK) {
        ret = obj->check(obj, inParamSet, outParamSet);
    }
    if (ret != CF_SUCCESS) {
        CF_LOG_E("do operation[%d] failed", opType);
    }
    return ret;
}

napi_value CommonOperation(napi_env env, napi_callback_info info, const CfObject *obj,
    int32_t opType, int32_t typeValue)
{
    CfParamSet *inParamSet = NULL;
    int32_t ret = GetInParamSet(env, info, opType, typeValue, inParamSet);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get param failed"));
        return nullptr;
    }

    CfParamSet *outParamSet = NULL;
    ret = DoOperation(obj, opType, inParamSet, &outParamSet);
    CfFreeParamSet(&inParamSet);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "do operation failed"));
        return nullptr;
    }

    napi_value returnValue = ConvertToNapiValue(env, opType, typeValue, outParamSet);
    if (returnValue == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "construct result failed"));
    }
    CfFreeParamSet(&outParamSet);
    return returnValue;
}
}  // namespace CertFramework
}  // namespace OHOS
