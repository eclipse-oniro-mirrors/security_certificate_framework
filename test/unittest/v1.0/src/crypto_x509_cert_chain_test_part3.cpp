/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include <openssl/pem.h>

#include "cert_crl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "securec.h"
#include "string"
#include "x509_cert_chain.h"
#include "x509_cert_chain_openssl.h"
#include "x509_certificate_openssl.h"

using namespace std;
using namespace testing::ext;
using namespace CFMock;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;

#ifdef __cplusplus
extern "C" {
#endif

int __real_BIO_do_connect_retry(BIO *b, int timeout, int retry);
void *__real_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);

void ResetMockFunctionPartOne(void)
{
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        BIO_do_connect_retry(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_BIO_do_connect_retry));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_get_ext_d2i(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
}

void ResetMockFunction(void)
{
    ResetMockFunctionPartOne();
}

#ifdef __cplusplus
}
#endif

namespace {
class CryptoX509CertChainTestPart3 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static CfBlob g_ocspDigest = { .size = static_cast<uint32_t>(strlen(g_digest) + 1),
    .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_digest)) };

static void FreeHcfRevocationCheckParam(HcfRevocationCheckParam *param)
{
    if (param == nullptr) {
        return;
    }

    if (param->options != nullptr) {
        if (param->options->data != nullptr) {
            CfFree(param->options->data);
        }

        CfFree(param->options);
    }

    if (param->ocspResponses != nullptr) {
        CfFree(param->ocspResponses);
    }

    if (param->ocspResponderCert != nullptr) {
        CfObjDestroy(param->ocspResponderCert);
    }

    CfFree(param);
}

static HcfRevocationCheckParam *ConstructHcfRevocationCheckParam(HcfRevChkOption *data, size_t size,
    CfBlob *ocspResponderURI = NULL, CfBlob *crlDownloadURI = NULL,
    const CfEncodingBlob *ocspResponderCertStream = NULL)
{
    HcfRevChkOpArray *revChkOpArray = (HcfRevChkOpArray *)CfMalloc(sizeof(HcfRevChkOpArray), 0);
    if (revChkOpArray == nullptr) {
        return nullptr;
    }

    revChkOpArray->count = size;
    revChkOpArray->data = (HcfRevChkOption *)CfMalloc(revChkOpArray->count * sizeof(HcfRevChkOption), 0);
    if (revChkOpArray->data == nullptr) {
        CfFree(revChkOpArray);
        return nullptr;
    }

    for (size_t i = 0; i < revChkOpArray->count; i++) {
        revChkOpArray->data[i] = data[i];
    }

    CfBlob *resp = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (resp == nullptr) {
        CfFree(revChkOpArray->data);
        CfFree(revChkOpArray);
        return nullptr;
    }
    resp->data = (uint8_t *)(&g_testOcspResponses[0]);
    resp->size = sizeof(g_testOcspResponses);

    HcfRevocationCheckParam *param = (HcfRevocationCheckParam *)CfMalloc(sizeof(HcfRevocationCheckParam), 0);
    if (param == nullptr) {
        CfFree(revChkOpArray->data);
        CfFree(revChkOpArray);
        return nullptr;
    }

    param->options = revChkOpArray;
    param->ocspResponses = resp;
    param->ocspResponderURI = ocspResponderURI;
    param->crlDownloadURI = crlDownloadURI;
    param->ocspDigest = &g_ocspDigest;

    if (ocspResponderCertStream != NULL) {
        (void)HcfX509CertificateCreate(&g_inStreamOcspResponderCert, &(param->ocspResponderCert));
        if (param->ocspResponderCert == nullptr) {
            FreeHcfRevocationCheckParam(param);
            return nullptr;
        }
    }

    return param;
}

void CryptoX509CertChainTestPart3::SetUpTestCase() {}

void CryptoX509CertChainTestPart3::TearDownTestCase() {}

void CryptoX509CertChainTestPart3::SetUp() {}

void CryptoX509CertChainTestPart3::TearDown() {}


HWTEST_F(CryptoX509CertChainTestPart3, ValidateOnlyCaCertTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOnlyCaCertTest001");
    HcfX509CertChainSpi *certChainPemOnlyCaCert = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainOnlyCenterCaCert, &certChainPemOnlyCaCert);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemOnlyCaCert, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainTrustAnchorCaCert, trustAnchorArray);


    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainPemOnlyCaCert->engineValidate(certChainPemOnlyCaCert, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemOnlyCaCert);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateOnlyCaCertTest002, TestSize.Level0)
{
    CF_LOG_I("ValidateOnlyCaCertTest002");
    HcfX509CertChainSpi *certChainPemWithOcsp = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChainWithOcsp, &certChainPemWithOcsp);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemWithOcsp, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inCaTrustCertWithOcspPem, trustAnchorArray);


    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemWithOcsp);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateOnlyCaCertTest003, TestSize.Level0)
{
    CF_LOG_I("ValidateOnlyCaCertTest003");
    HcfX509CertChainSpi *certChainPemWithOcsp = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChainWithOcsp, &certChainPemWithOcsp);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemWithOcsp, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inCaTrustCertWithOcspPem, trustAnchorArray);


    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    EXPECT_EQ(result.entityCert, nullptr);
    EXPECT_EQ(result.trustAnchor, nullptr);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemWithOcsp);
}
} // namespace
