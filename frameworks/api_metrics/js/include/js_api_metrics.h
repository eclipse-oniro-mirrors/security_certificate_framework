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

#ifndef JS_API_METRICS_H
#define JS_API_METRICS_H

#include <chrono>
#include <string>
#include "cf_result.h"

enum CfJsApiId {
    /* X509Cert */
    API_CREATE_X509_CERT,
    /* X509CRL */
    API_CREATE_X509_CRL_DEPRECATED,
    API_CREATE_X509_CRL,
    /* CertExtension */
    API_CREATE_CERT_EXTENSION,
    /* CertChainValidator */
    API_CREATE_CERT_CHAIN_VALIDATOR,
    API_CERT_CHAIN_VALIDATOR_VALIDATE,
    API_CERT_CHAIN_VALIDATOR_VALIDATE_CERT,
    /* CertCRLCollection */
    API_CREATE_CERT_CRL_COLLECTION,
    /* X509CertChain */
    API_CREATE_X509_CERT_CHAIN,
    API_X509_CERT_CHAIN_VALIDATE,
    API_BUILD_X509_CERT_CHAIN,
    /* X500DistinguishedName */
    API_CREATE_X500_DISTINGUISHED_NAME,
    /* Pkcs12 */
    API_PARSE_PKCS12,
    API_CREATE_PKCS12,
    API_CREATE_PKCS12_SYNC,
    /* TrustAnchors */
    API_CREATE_TRUST_ANCHORS_WITH_KEY_STORE,
    /* CmsGenerator */
    API_CREATE_CMS_GENERATOR,
    /* CmsParser */
    API_CREATE_CMS_PARSER,
    API_CERT_CMS_PARSER_VERIFY_SIGNED_DATA,
    API_CERT_CMS_PARSER_DECRYPT_ENVELOPED_DATA,
    /* CSR */
    API_GENERATE_CSR,
};

class HistogramScopeGuard {
public:
    explicit HistogramScopeGuard(CfJsApiId id);
    ~HistogramScopeGuard();
    void DisableScopeGuard();
    void SetErrorCode(CfResult code);
    std::pair<int32_t, int32_t> GetCodeValue(CfResult code) const;
    std::string GetApiName() const;

    HistogramScopeGuard(const HistogramScopeGuard &) = delete;
    HistogramScopeGuard &operator=(const HistogramScopeGuard &) = delete;

private:
    static void HistogramApiReport(const std::string &name, bool success, int32_t time,
        int32_t value, int32_t boundary);

    std::string name_;
    CfResult code_;
    std::chrono::steady_clock::time_point start_;
};

#endif /* JS_API_METRICS_H */
