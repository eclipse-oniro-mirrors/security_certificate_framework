/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "js_api_metrics.h"
#include <chrono>
#include <string>
#include <unordered_map>

#ifdef CERTIFICATE_FRAMEWORK_API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

#define CF "cert."

static const std::unordered_map<CfJsApiId, std::string> API_NAMES = {
    /* X509Cert */
    { API_CREATE_X509_CERT, CF "createX509Cert" },
    /* X509CRL */
    { API_CREATE_X509_CRL_DEPRECATED, CF "createX509Crl" },
    { API_CREATE_X509_CRL, CF "createX509CRL" },
    /* CertExtension */
    { API_CREATE_CERT_EXTENSION, CF "createCertExtension" },
    /* CertChainValidator */
    { API_CREATE_CERT_CHAIN_VALIDATOR, CF "createCertChainValidator" },
    { API_CERT_CHAIN_VALIDATOR_VALIDATE, CF "CertChainValidator.validate" },
    { API_CERT_CHAIN_VALIDATOR_VALIDATE_CERT, CF "CertChainValidator.validateCert" },
    /* CertCRLCollection */
    { API_CREATE_CERT_CRL_COLLECTION, CF "createCertCRLCollection" },
    /* X509CertChain */
    { API_CREATE_X509_CERT_CHAIN, CF "createX509CertChain" },
    { API_X509_CERT_CHAIN_VALIDATE, CF "X509CertChain.validate" },
    { API_BUILD_X509_CERT_CHAIN, CF "buildX509CertChain" },
    /* X500DistinguishedName */
    { API_CREATE_X500_DISTINGUISHED_NAME, CF "createX500DistinguishedName" },
    /* Pkcs12 */
    { API_PARSE_PKCS12, CF "parsePkcs12" },
    { API_CREATE_PKCS12, CF "createPkcs12" },
    { API_CREATE_PKCS12_SYNC, CF "createPkcs12Sync" },
    /* TrustAnchors */
    { API_CREATE_TRUST_ANCHORS_WITH_KEY_STORE, CF "createTrustAnchorsWithKeyStore" },
    /* CmsGenerator */
    { API_CREATE_CMS_GENERATOR, CF "createCmsGenerator" },
    /* CmsParser */
    { API_CREATE_CMS_PARSER, CF "createCmsParser" },
    { API_CERT_CMS_PARSER_VERIFY_SIGNED_DATA, CF "CmsParser.verifySignedData" },
    { API_CERT_CMS_PARSER_DECRYPT_ENVELOPED_DATA, CF "CmsParser.decryptEnvelopedData" },
    /* CSR */
    { API_GENERATE_CSR, CF "generateCsr" },
};

static const std::unordered_map<CfResult, int32_t> ERROR_CODES = {
    { CF_SUCCESS, 0 },                                  /* 0 */
    { CF_INVALID_PARAMS, 1 },                           /* 401 */
    { CF_NOT_SUPPORT, 2 },                              /* 801 */
    { CF_ERR_MALLOC, 3 },                               /* 19020001 */
    { CF_ERR_NAPI, 4 },                                 /* 19020002 */
    { CF_ERR_ANI, 4 },                                  /* 19020002 */
    { CF_ERR_INTERNAL, 4 },                             /* 19020002 */
    { CF_ERR_PARAMETER_CHECK, 5 },                      /* 19020003 */
    { CF_ERR_CRYPTO_OPERATION, 6 },                     /* 19030001 */
    { CF_ERR_CERT_SIGNATURE_FAILURE, 7 },               /* 19030002 */
    { CF_ERR_CERT_NOT_YET_VALID, 8 },                   /* 19030003 */
    { CF_ERR_CERT_HAS_EXPIRED, 9 },                     /* 19030004 */
    { CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, 10 },   /* 19030005 */
    { CF_ERR_KEYUSAGE_NO_CERTSIGN, 11 },                /* 19030006 */
    { CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, 12 },       /* 19030007 */
    { CF_ERR_CERT_INVALID_PRIVATE_KEY, 13 },            /* 19030008 */
    { CF_ERR_CERT_UNTRUSTED, 14 },                      /* 19030009 */
    { CF_ERR_CERT_REVOKED, 15 },                        /* 19030010 */
    { CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION, 16 },     /* 19030011 */
    { CF_ERR_CERT_HOST_NAME_MISMATCH, 17 },             /* 19030012 */
    { CF_ERR_CERT_EMAIL_MISMATCH, 18 },                 /* 19030013 */
    { CF_ERR_CERT_KEY_USAGE_MISMATCH, 19 },             /* 19030014 */
    { CF_ERR_CRL_NOT_FOUND, 20 },                       /* 19030015 */
    { CF_ERR_CRL_NOT_YET_VALID, 21 },                   /* 19030016 */
    { CF_ERR_CRL_HAS_EXPIRED, 22 },                     /* 19030017 */
    { CF_ERR_CRL_SIGNATURE_FAILURE, 23 },               /* 19030018 */
    { CF_ERR_UNABLE_TO_GET_CRL_ISSUER, 24 },            /* 19030019 */
    { CF_ERR_OCSP_RESPONSE_NOT_FOUND, 25 },             /* 19030020 */
    { CF_ERR_OCSP_RESPONSE_INVALID, 26 },               /* 19030021 */
    { CF_ERR_OCSP_SIGNATURE_FAILURE, 27 },              /* 19030022 */
    { CF_ERR_OCSP_CERT_STATUS_UNKNOWN, 28 },            /* 19030023 */
    { CF_ERR_NETWORK_TIMEOUT, 29 },                     /* 19030024 */
};

HistogramScopeGuard::HistogramScopeGuard(CfJsApiId id)
    : name_(""), code_(CF_SUCCESS), start_(std::chrono::steady_clock::now())
{
    auto it = API_NAMES.find(id);
    if (it != API_NAMES.end()) {
        name_ = it->second;
    }
}

HistogramScopeGuard::~HistogramScopeGuard()
{
    bool success = (code_ == CF_SUCCESS);
    auto [value, boundary] = GetCodeValue(code_);
    int32_t time = static_cast<int32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_).count());
    HistogramApiReport(name_, success, time, value, boundary);
}

void HistogramScopeGuard::DisableScopeGuard()
{
    name_.clear();
}

void HistogramScopeGuard::SetErrorCode(CfResult code)
{
    code_ = code;
}

std::pair<int32_t, int32_t> HistogramScopeGuard::GetCodeValue(CfResult code) const
{
    int32_t boundary = static_cast<int32_t>(ERROR_CODES.size());
    int32_t value = -1;
    auto it = ERROR_CODES.find(code);
    if (it != ERROR_CODES.end()) {
        value = it->second;
    }
    return { value, boundary };
}

std::string HistogramScopeGuard::GetApiName() const
{
    return name_;
}

void HistogramScopeGuard::HistogramApiReport(const std::string &name, bool success, int32_t time,
    int32_t value, int32_t boundary)
{
#ifdef CERTIFICATE_FRAMEWORK_API_METRICS_ENABLE
    if (!name.empty()) {
        HISTOGRAM_BOOLEAN((name + ".call").c_str(), success);
        if (success) {
            HISTOGRAM_TIMES((name + ".time").c_str(), time);
        }

        if (value > 0) {
            HISTOGRAM_ENUMERATION((name + ".errcode").c_str(), value, boundary);
        }
    }
#endif
}
