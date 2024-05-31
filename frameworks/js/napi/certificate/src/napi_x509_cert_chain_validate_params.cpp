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

#include "napi_x509_cert_chain_validate_params.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_type.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_crl_collection.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_object.h"
#include "napi_x509_trust_anchor.h"
#include "napi_x509_certificate.h"
#include "utils.h"
#include "x509_cert_chain_validate_params.h"

namespace OHOS {
namespace CertFramework {

static bool GetValidDate(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_DATE.c_str());
    if (obj == nullptr) {
        LOGI("prop date do not exist!");
        return true;
    }
    out = CertGetBlobFromStringJSParams(env, obj);
    if (out == nullptr) {
        LOGE("get blob failed!");
        return false;
    }
    return true;
}

static bool GetArrayLength(napi_env env, napi_value arg, uint32_t &length)
{
    bool flag = false;
    napi_status status = napi_is_array(env, arg, &flag);
    if (status != napi_ok || !flag) {
        LOGE("param type not array!");
        return false;
    }
    status = napi_get_array_length(env, arg, &length);
    if (status != napi_ok || length == 0 || length > MAX_LEN_OF_ARRAY) {
        LOGE("array length is invalid!");
        return false;
    }
    return true;
}

static bool GetX509TrustAnchorArray(napi_env env, napi_value arg, HcfX509TrustAnchorArray *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_TRUSTANCHORS.c_str());
    if (obj == nullptr) {
        LOGE("param type not array!");
        return false;
    }

    uint32_t length;
    if (!GetArrayLength(env, obj, length)) {
        LOGE("get array length failed!");
        return false;
    }

    out = static_cast<HcfX509TrustAnchorArray *>(CfMalloc(sizeof(HcfX509TrustAnchorArray), 0));
    if (out == nullptr) {
        LOGE("Failed to allocate out memory!");
        return false;
    }

    out->count = length;
    out->data = static_cast<HcfX509TrustAnchor **>(CfMalloc(length * sizeof(HcfX509TrustAnchor *), 0));
    if (out->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        CfFree(out);
        out = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element;
        if (napi_get_element(env, obj, i, &element) != napi_ok) {
            LOGE("get element failed!");
            CfFree(out->data);
            CfFree(out);
            out = nullptr;
            return false;
        }

        if (!BuildX509TrustAnchorObj(env, element, out->data[i])) {
            LOGE("get element failed!");
            CfFree(out->data);
            CfFree(out);
            out = nullptr;
            return false;
        }
    }
    return true;
}

static bool GetCertCRLCollectionArray(napi_env env, napi_value arg, HcfCertCRLCollectionArray *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_CERTCRLS.c_str());
    if (obj == nullptr) {
        LOGI("prop certCRLs do not exist!");
        return true;
    }

    uint32_t length;
    if (!GetArrayLength(env, obj, length)) {
        LOGE("get array length failed!");
        return false;
    }

    out = static_cast<HcfCertCRLCollectionArray *>(CfMalloc(sizeof(HcfCertCRLCollectionArray), 0));
    if (out == nullptr) {
        LOGE("Failed to allocate out memory!");
        return false;
    }
    out->count = length;
    out->data = static_cast<HcfCertCrlCollection **>(CfMalloc(length * sizeof(HcfCertCrlCollection *), 0));
    if (out->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        CfFree(out);
        out = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        napi_status status = napi_get_element(env, obj, i, &element);
        if (status != napi_ok) {
            LOGE("get element failed!");
            CfFree(out->data);
            CfFree(out);
            out = nullptr;
            return false;
        }
        NapiCertCRLCollection *napiCertCrlCollectionObj = nullptr;
        napi_unwrap(env, element, reinterpret_cast<void **>(&napiCertCrlCollectionObj));
        if (napiCertCrlCollectionObj == nullptr) {
            LOGE("napi cert crl collection object is nullptr!");
            CfFree(out->data);
            CfFree(out);
            out = nullptr;
            return false;
        }
        out->data[i] = napiCertCrlCollectionObj->GetCertCrlCollection();
    }
    return true;
}

static bool GetRevocationOptions(napi_env env, napi_value rckObj, HcfRevocationCheckParam *&out)
{
    napi_value obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OPTIONS.c_str());
    if (obj == nullptr) {
        return true;
    }
    bool flag = false;
    napi_status status = napi_is_array(env, obj, &flag);
    if (status != napi_ok || !flag) {
        return false;
    }

    uint32_t length = 0;
    status = napi_get_array_length(env, obj, &length);
    if (status != napi_ok || length == 0 || length > MAX_NAPI_ARRAY_OF_U8ARR) {
        return false;
    }
    out->options = static_cast<HcfRevChkOpArray *>(CfMalloc(sizeof(HcfRevChkOpArray), 0));
    if (out->options == nullptr) {
        return false;
    }
    out->options->count = length;
    out->options->data = static_cast<HcfRevChkOption *>(CfMalloc(length * sizeof(HcfRevChkOption), 0));
    if (out->options->data == nullptr) {
        CfFree(out->options);
        out->options = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        if (napi_get_element(env, obj, i, &element) != napi_ok ||
            napi_get_value_int32(env, element, (int32_t *)&(out->options->data[i])) != napi_ok) {
            CfFree(out->options->data);
            CfFree(out->options);
            return false;
        }
        switch (out->options->data[i]) {
            case REVOCATION_CHECK_OPTION_PREFER_OCSP:
            case REVOCATION_CHECK_OPTION_ACCESS_NETWORK:
            case REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER:
            case REVOCATION_CHECK_OPTION_FALLBACK_LOCAL:
                break;
            default:
                CfFree(out->options->data);
                out->options->data = nullptr;
                CfFree(out->options);
                out->options = nullptr;
                return false;
        }
    }
    return true;
}

static bool GetRevocationocspDigest(napi_env env, napi_value rckObj, HcfRevocationCheckParam *&out)
{
    napi_value obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_DIGEST.c_str());
    if (obj == nullptr) {
        return true;
    }

    out->ocspDigest = CertGetBlobFromStringJSParams(env, obj);
    if (out->ocspDigest == nullptr) {
        return false;
    }

    char *mdName = (char *)out->ocspDigest->data;
    if (strcmp(mdName, "SHA1") == 0) {
        return true;
    } else if (strcmp(mdName, "SHA224") == 0) {
        return true;
    } else if (strcmp(mdName, "SHA256") == 0) {
        return true;
    } else if (strcmp(mdName, "SHA384") == 0) {
        return true;
    } else if (strcmp(mdName, "SHA512") == 0) {
        return true;
    } else if (strcmp(mdName, "MD5") == 0) {
        return true;
    }

    CfFree(out->ocspDigest->data);
    out->ocspDigest->data = nullptr;
    CfFree(out->ocspDigest);
    out->ocspDigest = nullptr;
    return false;
}

static bool GetRevocationDetail(napi_env env, napi_value rckObj, HcfRevocationCheckParam *&out)
{
    napi_value obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_REQ_EXTENSION.c_str());
    if (obj != nullptr) {
        out->ocspRequestExtension = CertGetBlobArrFromArrUarrJSParams(env, obj);
        if (out->ocspRequestExtension == nullptr) {
            return false;
        }
    }
    obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_RESP_URI.c_str());
    if (obj != nullptr) {
        out->ocspResponderURI = CertGetBlobFromStringJSParams(env, obj);
        if (out->ocspResponderURI == nullptr) {
            return false;
        }
    }
    obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_RESP_CERT.c_str());
    if (obj != nullptr) {
        NapiX509Certificate *napiX509Cert = nullptr;
        napi_unwrap(env, obj, reinterpret_cast<void **>(&napiX509Cert));
        if (napiX509Cert != nullptr) {
            out->ocspResponderCert = napiX509Cert->GetX509Cert();
            if (out->ocspResponderCert == nullptr) {
                return false;
            }
        } else {
            return false;
        }
    }
    obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_RESPS.c_str());
    if (obj != nullptr) {
        out->ocspResponses = CertGetBlobFromUint8ArrJSParams(env, obj);
        if (out->ocspResponses == nullptr) {
            return false;
        }
    }
    obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_CRL_DOWNLOAD_URI.c_str());
    if (obj != nullptr) {
        out->crlDownloadURI = CertGetBlobFromStringJSParams(env, obj);
        if (out->crlDownloadURI == nullptr) {
            return false;
        }
    }
    if (!GetRevocationocspDigest(env, rckObj, out)) {
        return false;
    }
    return GetRevocationOptions(env, rckObj, out);
}

static bool GetRevocationCheckParam(napi_env env, napi_value arg, HcfRevocationCheckParam *&out)
{
    napi_value rckObj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_REVOCATIONCHECKPARAM.c_str());
    if (rckObj == nullptr) {
        LOGI("RevocationCheckParam do not exist!");
        return true;
    }
    napi_valuetype valueType;
    napi_typeof(env, rckObj, &valueType);
    if (valueType == napi_null || valueType != napi_object) {
        LOGE("Failed to check input param!");
        return false;
    }

    out = static_cast<HcfRevocationCheckParam *>(CfMalloc(sizeof(HcfRevocationCheckParam), 0));
    if (out == nullptr) {
        LOGE("Failed to allocate out memory!");
        return false;
    }
    if (!GetRevocationDetail(env, rckObj, out)) {
        LOGE("Failed to get revocation detail!");
        CfFree(out);
        return false;
    }

    return true;
}

static bool GetValidationPolicyType(napi_env env, napi_value arg, HcfValPolicyType &out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_POLICY.c_str());
    if (obj != nullptr) {
        napi_status status = napi_get_value_int32(env, obj, (int32_t *)&out);
        if (status != napi_ok) {
            return false;
        }
    }
    return true;
}

static bool GetSSLHostname(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_SSLHOSTNAME.c_str());
    if (obj == nullptr) {
        LOGI("Param type not SSLHostname!");
        return true;
    }
    out = CertGetBlobFromStringJSParams(env, obj);
    if (out == nullptr) {
        LOGE("SSLHostname is nullptr");
        return false;
    }
    return true;
}

static bool GetKeyUsage(napi_env env, napi_value arg, HcfKuArray *&out)
{
    out = nullptr;
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_KEYUSAGE.c_str());
    if (obj == nullptr) {
        return true;
    }
    bool flag = false;
    napi_status status = napi_is_array(env, obj, &flag);
    if (status != napi_ok || !flag) {
        return false;
    }
    uint32_t length = 0;
    status = napi_get_array_length(env, obj, &length);
    if (status != napi_ok || length == 0 || length > MAX_NAPI_ARRAY_OF_U8ARR) {
        return false;
    }
    out = static_cast<HcfKuArray *>(CfMalloc(sizeof(HcfKuArray), 0));
    if (out == nullptr) {
        return false;
    }
    out->count = length;
    out->data = static_cast<HcfKeyUsageType *>(CfMalloc(length * sizeof(HcfKeyUsageType), 0));
    if (out->data == nullptr) {
        CfFree(out);
        out = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        if (napi_get_element(env, obj, i, &element) != napi_ok ||
            napi_get_value_int32(env, element, (int32_t *)&(out->data[i])) != napi_ok) {
            CfFree(out);
            out = nullptr;
            return false;
        }
    }
    return true;
}

void FreeX509CertChainValidateParams(HcfX509CertChainValidateParams &param)
{
    CfBlobFree(&param.date);
    if (param.trustAnchors != nullptr) {
        for (uint32_t i = 0; i < param.trustAnchors->count; ++i) {
            FreeX509TrustAnchorObj(param.trustAnchors->data[i]);
        }
        CfFree(param.trustAnchors);
        param.trustAnchors = nullptr;
    }

    if (param.certCRLCollections != nullptr) {
        CfFree(param.certCRLCollections->data);
        CfFree(param.certCRLCollections);
        param.certCRLCollections = nullptr;
    }
}

void FreeTrustAnchorArray(HcfX509TrustAnchorArray *trustAnchorArray, bool freeCertFlag)
{
    if (trustAnchorArray == NULL) {
        return;
    }
    for (uint32_t i = 0; i < trustAnchorArray->count; i++) {
        if (trustAnchorArray->data[i] != NULL) {
            if (freeCertFlag) {
                CfObjDestroy(trustAnchorArray->data[i]->CACert);
            }
            trustAnchorArray->data[i]->CACert = NULL;
            CfBlobFree(&trustAnchorArray->data[i]->CASubject);
            CfBlobFree(&trustAnchorArray->data[i]->nameConstraints);
            CfFree(trustAnchorArray->data[i]);
            trustAnchorArray->data[i] = NULL;
        }
    }

    CfFree(trustAnchorArray);
}

bool BuildX509CertChainValidateParams(napi_env env, napi_value arg, HcfX509CertChainValidateParams &param)
{
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type != napi_object) {
        LOGE("wrong argument type. expect string type. [Type]: %d", type);
        return false;
    }

    if (!GetValidDate(env, arg, param.date)) {
        LOGE("GetValidDate failed");
        return false;
    }
    if (!GetX509TrustAnchorArray(env, arg, param.trustAnchors)) {
        LOGE("GetX509TrustAnchorArray failed");
        return false;
    }
    if (!GetCertCRLCollectionArray(env, arg, param.certCRLCollections)) {
        LOGE("GetCertCRLCollectionArray failed");
        return false;
    }
    if (!GetRevocationCheckParam(env, arg, param.revocationCheckParam)) {
        LOGE("Get revocation check param failed!");
        return false;
    }
    if (!GetValidationPolicyType(env, arg, param.policy)) {
        LOGE("Get validation policy type failed!");
        return false;
    }
    if (!GetSSLHostname(env, arg, param.sslHostname)) {
        LOGE("Get SSLHostname failed!");
        return false;
    }
    if (!GetKeyUsage(env, arg, param.keyUsage)) {
        LOGE("Get key usage failed!");
        return false;
    }

    return true;
}

} // namespace CertFramework
} // namespace OHOS
