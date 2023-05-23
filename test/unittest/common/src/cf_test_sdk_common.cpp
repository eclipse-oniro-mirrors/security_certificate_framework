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

#include "cf_test_sdk_common.h"

#include <string>
#include <iostream>

#include "cf_api.h"
#include "cf_param.h"
#include "cf_result.h"

int32_t CertframeworkSdkTest::TestConstructParamSetIn(const CfParam *params, uint32_t cnt, CfParamSet **paramSet)
{
    CfParamSet *tmp = NULL;
    int32_t ret = CfInitParamSet(&tmp);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    ret = CfAddParams(tmp, params, cnt);
    if (ret != CF_SUCCESS) {
        CfFreeParamSet(&tmp);
        return ret;
    }

    ret = CfBuildParamSet(&tmp);
    if (ret != CF_SUCCESS) {
        CfFreeParamSet(&tmp);
        return ret;
    }

    *paramSet = tmp;
    return CF_SUCCESS;
}

int32_t CertframeworkSdkTest::CommonTest(CfObjectType type, const CfEncodingBlob *inData,
    const CfParam *params, uint32_t cnt, CfParamSet **outParamSet)
{
    CfObject *object = nullptr;
    int32_t ret = CfCreate(type, inData, &object);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    CfParamSet *inParamSet = nullptr;
    ret = TestConstructParamSetIn(params, cnt, &inParamSet);
    if (ret != CF_SUCCESS) {
        object->destroy(&object);
        return ret;
    }

    if (params[0].tag == CF_TAG_GET_TYPE) {
        ret = object->get(object, inParamSet, outParamSet);
    } else {
        ret = object->check(object, inParamSet, outParamSet);
    }

    object->destroy(&object);
    CfFreeParamSet(&inParamSet);
    return ret;
}

int32_t CertframeworkSdkTest::AbnormalTest(CfObjectType objType, const CfEncodingBlob *in,
    const CfParam *params, uint32_t cnt, int32_t optype)
{
    CfObject *abnormalObject = nullptr;
    int32_t ret = CfCreate(objType, in, &abnormalObject);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    CfParamSet *inParamSet = nullptr;
    ret = TestConstructParamSetIn(params, cnt, &inParamSet);
    if (ret != CF_SUCCESS) {
        abnormalObject->destroy(&abnormalObject);
        return ret;
    }

    CfParamSet *outParamSet = nullptr;
    if (optype == OP_TYPE_CHECK) {
        ret = abnormalObject->check(abnormalObject, inParamSet, &outParamSet);
    } else if (optype == OP_TYPE_GET) {
        ret = abnormalObject->get(abnormalObject, inParamSet, &outParamSet);
    }

    abnormalObject->destroy(&abnormalObject);
    CfFreeParamSet(&inParamSet);
    if (ret == CF_SUCCESS) {
        return CF_NOT_SUPPORT; /* expect not success */
    }

    return CF_SUCCESS;
}


#ifdef TEST_PRINT_DATA
static void print_blob(const uint8_t *data, uint32_t len)
{
    printf("len %u", len);
    for (uint32_t i = 0; i < len; i++) {
        if ((i % 16) == 0) { /* Line breaks every 16 characters */
            printf("\n");
        }
        printf("0x%02x, ", data[i]);
    }
    printf("\r\n");
}

int32_t CertframeworkSdkTest::GetOutValue(const CfParamSet *resultParamSet)
{
    CfParam *param = NULL;
    int32_t ret = CfGetParam(resultParamSet, CF_TAG_RESULT_TYPE, &param);
    if (ret != CF_SUCCESS) {
        std::cout << "get CF_TAG_RESULT_TYPE failed" << std::endl;
        return ret;
    }

    int32_t type = param->int32Param;
    CfParam *paramOut = NULL;
    switch (type) {
        case CF_TAG_TYPE_INT:
            ret = CfGetParam(resultParamSet, CF_TAG_RESULT_INT, &paramOut);
            if (ret == CF_SUCCESS) {
                std::cout << "value: " << paramOut->int32Param << std::endl;
            }
            break;
        case CF_TAG_TYPE_UINT:
            ret = CfGetParam(resultParamSet, CF_TAG_RESULT_UINT, &paramOut);
            if (ret == CF_SUCCESS) {
                std::cout << "value: " << paramOut->uint32Param << std::endl;
            }
            break;
        case CF_TAG_TYPE_ULONG:
            ret = CfGetParam(resultParamSet, CF_TAG_RESULT_ULONG, &paramOut);
            if (ret == CF_SUCCESS) {
                std::cout << "value: " << paramOut->uint64Param << std::endl;
            }
            break;
        case CF_TAG_TYPE_BOOL:
            ret = CfGetParam(resultParamSet, CF_TAG_RESULT_BOOL, &paramOut);
            if (ret == CF_SUCCESS) {
                std::cout << "value: " << paramOut->boolParam << std::endl;
            }
            break;
        case CF_TAG_TYPE_BYTES:
            for (uint32_t i = 0; i < resultParamSet->paramsCnt; i++) {
                if (CfGetTagType((CfTag)(resultParamSet->params[i].tag)) == CF_TAG_TYPE_BYTES) {
                    std::cout << "i: " << i << " ";
                    print_blob(resultParamSet->params[i].blob.data, resultParamSet->params[i].blob.size);
                }
            }
            break;
        default:
            ret = CF_INVALID_PARAMS;
            break;
    }
    return ret;
}
#endif

