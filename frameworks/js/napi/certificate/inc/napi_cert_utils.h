/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef NAPI_CERT_UILTS_H
#define NAPI_CERT_UILTS_H

#include <cstdint>
#include <string>

#include "cert_chain_validator.h"
#include "cf_blob.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_defines.h"
#include "x509_cert_match_parameters.h"

namespace OHOS {
namespace CertFramework {

constexpr size_t MAX_NAPI_ARRAY_OF_U8ARR = 1024;

inline void CertAddUint32Property(napi_env env, napi_value object, const char *name, uint32_t value)
{
    napi_value property = nullptr;
    napi_create_uint32(env, value, &property);
    napi_set_named_property(env, object, name, property);
}

CfBlob *CertGetBlobFromNapiValue(napi_env env, napi_value arg);
napi_value CertConvertBlobToNapiValue(napi_env env, CfBlob *blob);
napi_value ConvertBlobToUint8ArrNapiValue(napi_env env, CfBlob *blob);
napi_value GetProp(napi_env env, napi_value arg, const char *name);
CfBlob *CertGetBlobFromUint8ArrJSParams(napi_env env, napi_value arg);
CfBlob *CertGetBlobFromStringJSParams(napi_env env, napi_value arg);
CfBlob *CertGetBlobFromArrBoolJSParams(napi_env env, napi_value arg);
SubAltNameArray *CertGetSANArrFromArrUarrJSParams(napi_env env, napi_value arg);
CfArray *CertGetArrFromArrUarrJSParams(napi_env env, napi_value arg);
bool CertGetBlobFromBigIntJSParams(napi_env env, napi_value arg, CfBlob &outBlob);
bool CertGetSerialNumberFromBigIntJSParams(napi_env env, napi_value arg, CfBlob &outBlob);
CfBlobArray *CertGetBlobArrFromArrUarrJSParams(napi_env env, napi_value arg);
bool CertGetStringFromJSParams(napi_env env, napi_value arg, std::string &returnStr);
bool CertGetInt32FromJSParams(napi_env env, napi_value arg, int32_t &returnInt);
bool CertGetCallbackFromJSParams(napi_env env, napi_value arg, napi_ref *returnCb);
bool GetEncodingBlobFromValue(napi_env env, napi_value object, CfEncodingBlob **encodingBlob);
bool GetCertChainFromValue(napi_env env, napi_value object, HcfCertChainData **certChainData);
bool CertCheckArgsCount(napi_env env, size_t argc, size_t expectedCount, bool isSync);
AsyncType GetAsyncType(napi_env env, size_t argc, size_t maxCount, napi_value arg);
napi_value CertGetResourceName(napi_env env, const char *name);
napi_value GenerateArrayBuffer(napi_env env, uint8_t *data, uint32_t size);
napi_value CertNapiGetNull(napi_env env);
napi_value ConvertArrayToNapiValue(napi_env env, CfArray *array);
napi_value ConvertEncodingBlobToNapiValue(napi_env env, CfEncodingBlob *encodingBlob);
napi_value CertGenerateBusinessError(napi_env env, int32_t errCode, const char *errMsg);
napi_value ConvertBlobToNapiValue(napi_env env, const CfBlob *blob);
napi_value ConvertBlobToBigIntWords(napi_env env, const CfBlob &blob);
napi_value ConvertBlobToInt64(napi_env env, const CfBlob &blob);
napi_value ConvertArrayStringToNapiValue(napi_env env, CfArray *array);
bool ConvertBlobToEncodingBlob(const CfBlob &blob, CfEncodingBlob *encodingBlob);
}  // namespace CertFramework
}  // namespace OHOS
#endif
