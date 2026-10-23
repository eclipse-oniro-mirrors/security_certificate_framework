/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CRYPTO_X509_CERT_VALIDATOR_TEST_COMMON_H
#define CRYPTO_X509_CERT_VALIDATOR_TEST_COMMON_H

#include <gtest/gtest.h>
#include <securec.h>
#include <string>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "cert_chain_validator.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "x509_certificate.h"
#include "crypto_x509_cert_chain_data_pem_added.h"
#include "crypto_x509_cert_chain_data_pem_ex.h"
#include "crypto_x509_cert_validator_test_data.h"

extern HcfCertChainValidator *g_validator;

class CryptoX509CertValidatorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

HcfX509Certificate *CreateCertFromPem(const char *pemCert);
void FreeVerifyCertResult(HcfCertVerifyResult &result);
void FreeValidatorParams(HcfX509CertValidatorParams &params);
void FreeValidatorParamsWithOcspData(HcfX509CertValidatorParams &params);
OCSP_RESPONSE *CreateOcspResponseFromDer(const uint8_t *der, size_t len);

/* Helper functions for test setup */
HcfX509Certificate *SetupCertWithTrustAnchor(const char *pemCert, HcfX509CertValidatorParams &params);
void SetupKeyUsageParams(HcfX509CertValidatorParams &params, int32_t *values, uint32_t count);
void SetupHostnameParams(HcfX509CertValidatorParams &params, const char *hostname);
void SetupEmailParams(HcfX509CertValidatorParams &params, const char *email);
void SetupCrlCheckParams(HcfX509CertValidatorParams &params, bool allowDownload);
void SetupOcspCheckParams(HcfX509CertValidatorParams &params, bool allowOnline);

#endif