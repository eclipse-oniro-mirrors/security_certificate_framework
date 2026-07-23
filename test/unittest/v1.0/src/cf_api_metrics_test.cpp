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

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <unordered_map>
#include "js_api_metrics.h"

using namespace testing::ext;

namespace {
class CfJsApiMetricsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(CfJsApiMetricsTest, HistogramApiReport001, TestSize.Level1)
{
    static const std::unordered_map<CfJsApiId, std::string> items = {
        { API_CREATE_X509_CERT, "cert.createX509Cert" },
        { API_CREATE_CERT_CHAIN_VALIDATOR, "cert.createCertChainValidator" },
        { API_CERT_CHAIN_VALIDATOR_VALIDATE, "cert.CertChainValidator.validate" },
        { API_GENERATE_CSR, "cert.generateCsr" },
        { API_CREATE_CMS_GENERATOR, "cert.createCmsGenerator" },
    };

    for (const auto &iter : items) {
        HistogramScopeGuard guard(iter.first);
        std::string name = guard.GetApiName();
        EXPECT_EQ(name, iter.second);
    }
}

HWTEST_F(CfJsApiMetricsTest, HistogramApiReport002, TestSize.Level1)
{
    static const std::unordered_map<CfResult, int32_t> items = {
        { CF_SUCCESS, 0 },
        { CF_INVALID_PARAMS, 1 },
        { CF_NOT_SUPPORT, 2 },
        { CF_ERR_MALLOC, 3 },
        { CF_ERR_NAPI, 4 },
        { CF_ERR_ANI, 4 },
        { CF_ERR_INTERNAL, 4 },
        { CF_ERR_PARAMETER_CHECK, 5 },
        { CF_ERR_CRYPTO_OPERATION, 6 },
        { CF_ERR_CERT_SIGNATURE_FAILURE, 7 },
        { CF_ERR_CERT_NOT_YET_VALID, 8 },
        { CF_ERR_CERT_HAS_EXPIRED, 9 },
        { CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, 10 },
        { CF_ERR_KEYUSAGE_NO_CERTSIGN, 11 },
        { CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, 12 },
        { CF_ERR_CERT_INVALID_PRIVATE_KEY, 13 },
        { CF_ERR_CERT_UNTRUSTED, 14 },
        { CF_ERR_CERT_REVOKED, 15 },
        { CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION, 16 },
        { CF_ERR_CERT_HOST_NAME_MISMATCH, 17 },
        { CF_ERR_CERT_EMAIL_MISMATCH, 18 },
        { CF_ERR_CERT_KEY_USAGE_MISMATCH, 19 },
        { CF_ERR_CRL_NOT_FOUND, 20 },
        { CF_ERR_CRL_NOT_YET_VALID, 21 },
        { CF_ERR_CRL_HAS_EXPIRED, 22 },
        { CF_ERR_CRL_SIGNATURE_FAILURE, 23 },
        { CF_ERR_UNABLE_TO_GET_CRL_ISSUER, 24 },
        { CF_ERR_OCSP_RESPONSE_NOT_FOUND, 25 },
        { CF_ERR_OCSP_RESPONSE_INVALID, 26 },
        { CF_ERR_OCSP_SIGNATURE_FAILURE, 27 },
        { CF_ERR_OCSP_CERT_STATUS_UNKNOWN, 28 },
        { CF_ERR_NETWORK_TIMEOUT, 29 },
    };

    HistogramScopeGuard guard(API_CREATE_X509_CERT);
    for (const auto &iter : items) {
        auto [value, boundary] = guard.GetCodeValue(iter.first);
        EXPECT_EQ(value, iter.second);
        EXPECT_EQ(boundary, 31);
    }
}

HWTEST_F(CfJsApiMetricsTest, HistogramApiReport003, TestSize.Level1)
{
    HistogramScopeGuard guard(API_CREATE_X509_CERT);
    guard.SetErrorCode(CF_ERR_ANI);
    auto [value, boundary] = guard.GetCodeValue(CF_ERR_ANI);
    EXPECT_EQ(value, 4);
    EXPECT_EQ(boundary, 31);
    std::string name = guard.GetApiName();
    EXPECT_EQ(name, "cert.createX509Cert");
    guard.DisableScopeGuard();
    name = guard.GetApiName();
    EXPECT_EQ(name, "");
}
}
