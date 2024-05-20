/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "napi_x509_cert_match_parameters.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_type.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_object.h"
#include "napi_x509_certificate.h"
#include "utils.h"

namespace OHOS {
namespace CertFramework {

static bool GetValidDate(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_VALID_DATE.c_str());
    if (obj == nullptr) {
        return true;
    }

    out = CertGetBlobFromStringJSParams(env, obj);
    if (out == nullptr) {
        LOGE("out is nullptr");
        return false;
    }
    return true;
}

static bool GetIssuer(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_ISSUER.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromUint8ArrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("out is nullptr");
        return false;
    }
    return true;
}

static bool GetKeyUsage(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_KEY_USAGE.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromArrBoolJSParams(env, obj);
    if (out == nullptr) {
        LOGE("out is nullptr");
        return false;
    }
    return true;
}

static bool GetSerialNumber(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_SERIAL_NUMBER.c_str());
    if (obj == nullptr) {
        return true;
    }
    CfBlob outBlob = { 0, nullptr };
    bool flag = CertGetSerialNumberFromBigIntJSParams(env, obj, outBlob);
    if (!flag || outBlob.data == nullptr || outBlob.size == 0) {
        LOGE("out is nullptr");
        return false;
    }
    out = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (out == nullptr) {
        LOGE("Failed to allocate newBlob memory!");
        CfBlobDataFree(&outBlob);
        return false;
    }
    out->data = outBlob.data;
    out->size = outBlob.size;
    return true;
}

static bool GetSubject(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_SUBJECT.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromUint8ArrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("out is nullptr");
        return false;
    }
    return true;
}

static bool GetPublicKey(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_PUBLIC_KEY.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromNapiValue(env, obj);
    if (out == nullptr) {
        LOGE("out is nullptr");
        return false;
    }
    return true;
}

static bool GetPublicKeyAlgId(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_PUBLIC_KEY_ALGID.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromStringJSParams(env, obj);
    if (out == nullptr) {
        LOGE("out is nullptr");
        return false;
    }
    return true;
}

static bool GetX509Cert(napi_env env, napi_value arg, HcfCertificate *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_X509CERT.c_str());
    if (obj == nullptr) {
        return true;
    }
    NapiX509Certificate *napiX509Cert = nullptr;
    napi_unwrap(env, obj, reinterpret_cast<void **>(&napiX509Cert));
    if (napiX509Cert == nullptr) {
        LOGE("napiX509Cert is null!");
        return false;
    }

    HcfX509Certificate *cert = napiX509Cert->GetX509Cert();
    if (cert == nullptr) {
        LOGE("cert is null!");
        return false;
    }
    LOGI("x509Cert is not null!");
    out = &(cert->base);
    return true;
}

static bool GetSubjectAltNamesArray(napi_env env, napi_value arg, SubAltNameArray *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_SUBJECT_ALT_NAMES.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetSANArrFromArrUarrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("Failed to get subject alternative name array!");
        return false;
    }
    return true;
}

static bool GetMatchAllSubjectAltNames(napi_env env, napi_value arg, bool &out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_MATCH_ALL_SUBJECT.c_str());
    if (obj == nullptr) {
        return true;
    }

    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType != napi_boolean) {
        LOGE("Get %s obj is not bool!", CERT_MATCH_TAG_MATCH_ALL_SUBJECT.c_str());
        return false;
    }

    napi_status status = napi_get_value_bool(env, obj, &out);
    if (status != napi_ok) {
        LOGE("Failed to get value bool!");
        return false;
    }
    return true;
}

static bool GetAuthorityKeyIdentifier(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_AUTH_KEY_ID.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromUint8ArrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("Out is nullptr");
        return false;
    }
    return true;
}

static bool GetMinPathLenConstraint(napi_env env, napi_value arg, int32_t &out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_MIN_PATH_LEN.c_str());
    if (obj == nullptr) {
        out = -1; // default value
        return true;
    }
    napi_status status = napi_get_value_int32(env, obj, &out);
    if (status != napi_ok) {
        LOGE("Failed to get value int32!");
        return false;
    }
    return true;
}

static bool GetExtendedKeyUsage(napi_env env, napi_value arg, CfArray *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_EXTENDED_KEY_USAGE.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetArrFromArrUarrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("Out is nullptr");
        return false;
    }
    return true;
}

static bool GetNameConstraints(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_NAME_CONSTRAINTS.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromUint8ArrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("Out is nullptr");
        return false;
    }
    return true;
}

static bool GetCertPolicy(napi_env env, napi_value arg, CfArray *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_CERT_POLICY.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetArrFromArrUarrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("Out is nullptr");
        return false;
    }
    return true;
}

static bool GetPrivateKeyValid(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_PRIVATE_KEY_VALID.c_str());
    if (obj == nullptr) {
        return true;
    }

    out = CertGetBlobFromStringJSParams(env, obj);
    if (out == nullptr) {
        LOGE("Out is nullptr");
        return false;
    }
    return true;
}

static bool GetSubjectKeyIdentifier(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_SUBJECT_KEY_IDENTIFIER.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromUint8ArrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("Out is nullptr.");
        return false;
    }
    return true;
}

bool BuildX509CertMatchParamsV1(napi_env env, napi_value arg, HcfX509CertMatchParams *&matchParams)
{
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type != napi_object) {
        LOGE("Wrong argument type. expect object type. [Type]: %d", type);
        return false;
    }
    if (!GetValidDate(env, arg, matchParams->validDate)) {
        return false;
    }
    if (!GetIssuer(env, arg, matchParams->issuer)) {
        return false;
    }
    if (!GetKeyUsage(env, arg, matchParams->keyUsage)) {
        return false;
    }
    if (!GetSerialNumber(env, arg, matchParams->serialNumber)) {
        return false;
    }
    if (!GetSubject(env, arg, matchParams->subject)) {
        return false;
    }
    if (!GetPublicKey(env, arg, matchParams->publicKey)) {
        return false;
    }
    if (!GetPublicKeyAlgId(env, arg, matchParams->publicKeyAlgID)) {
        return false;
    }
    if (!GetX509Cert(env, arg, matchParams->x509Cert)) {
        return false;
    }
    return true;
}

bool BuildX509CertMatchParamsV2(napi_env env, napi_value arg, HcfX509CertMatchParams *&matchParams)
{
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type != napi_object) {
        LOGE("Wrong argument type. expect object type. [Type]: %d", type);
        return false;
    }
    if (!GetSubjectAltNamesArray(env, arg, matchParams->subjectAlternativeNames)) {
        return false;
    }
    if (!GetMatchAllSubjectAltNames(env, arg, matchParams->matchAllSubjectAltNames)) {
        return false;
    }
    if (!GetAuthorityKeyIdentifier(env, arg, matchParams->authorityKeyIdentifier)) {
        return false;
    }
    if (!GetMinPathLenConstraint(env, arg, matchParams->minPathLenConstraint)) {
        return false;
    }
    if (!GetExtendedKeyUsage(env, arg, matchParams->extendedKeyUsage)) {
        return false;
    }
    if (!GetNameConstraints(env, arg, matchParams->nameConstraints)) {
        return false;
    }
    if (!GetCertPolicy(env, arg, matchParams->certPolicy)) {
        return false;
    }
    if (!GetPrivateKeyValid(env, arg, matchParams->privateKeyValid)) {
        return false;
    }
    if (!GetSubjectKeyIdentifier(env, arg, matchParams->subjectKeyIdentifier)) {
        return false;
    }
    return true;
}

bool BuildX509CertMatchParams(napi_env env, napi_value arg, HcfX509CertMatchParams *&matchParams)
{
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type != napi_object) {
        LOGE("wrong argument type. expect object type. [Type]: %d", type);
        return false;
    }
    if (!BuildX509CertMatchParamsV1(env, arg, matchParams)) {
        return false;
    }
    if (!BuildX509CertMatchParamsV2(env, arg, matchParams)) {
        return false;
    }

    return true;
}

void FreeX509CertMatchParams(HcfX509CertMatchParams *&matchParams)
{
    if (matchParams == nullptr) {
        return;
    }

    matchParams->x509Cert = nullptr;
    CfBlobFree(&matchParams->validDate);
    CfBlobFree(&matchParams->issuer);
    CfBlobFree(&matchParams->keyUsage);
    CfBlobFree(&matchParams->serialNumber);
    CfBlobFree(&matchParams->subject);
    CfBlobFree(&matchParams->publicKey);
    CfBlobFree(&matchParams->publicKeyAlgID);
    CfBlobFree(&matchParams->authorityKeyIdentifier);
    CfBlobFree(&matchParams->nameConstraints);
    CfBlobFree(&matchParams->privateKeyValid);
    CfBlobFree(&matchParams->subjectKeyIdentifier);
    CfArrayDataClearAndFree(matchParams->certPolicy);
    CfArrayDataClearAndFree(matchParams->extendedKeyUsage);
    CfFree(matchParams->certPolicy);
    CfFree(matchParams->extendedKeyUsage);
    if (matchParams->subjectAlternativeNames != nullptr) {
        for (uint32_t i = 0; i < matchParams->subjectAlternativeNames->count; ++i) {
            if (matchParams->subjectAlternativeNames->data != nullptr) {
                CF_FREE_BLOB(matchParams->subjectAlternativeNames->data[i].name);
            }
        }
        CfFree(matchParams->subjectAlternativeNames->data);
        CfFree(matchParams->subjectAlternativeNames);
    }

    CF_FREE_PTR(matchParams);
}

} // namespace CertFramework
} // namespace OHOS
