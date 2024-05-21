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

int __real_OPENSSL_sk_num(const OPENSSL_STACK *st);
void *__real_OPENSSL_sk_value(const OPENSSL_STACK *st, int i);
int __real_OPENSSL_sk_push(OPENSSL_STACK *st, const int data);
OPENSSL_STACK *__real_OPENSSL_sk_new_null(void);
void *__real_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
X509_CRL *__real_X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);
OCSP_REQUEST *__real_OCSP_REQUEST_new(void);
struct stack_st_OPENSSL_STRING *__real_X509_get1_ocsp(X509 *x);
int __real_OSSL_HTTP_parse_url(const char *url, int *pssl, char **puser, char **phost, char **pport, int *pport_num,
    char **ppath, char **pquery, char **pfrag);

#ifdef __cplusplus
}
#endif

namespace {
class CryptoX509CertChainTestPart2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static HcfX509CertChainSpi *g_certChainPemSpi = nullptr;
static HcfX509CertChainSpi *g_certChainPemSpi163 = nullptr;

static CfBlob g_blobDownloadURI = { .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_crlDownloadURI)),
    .size = strlen(g_crlDownloadURI) + 1 };

static CfBlob g_blobDownloadURIHttps = { .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_crlDownloadURIHttps)),
    .size = strlen(g_crlDownloadURIHttps) + 1 };

static CfBlob g_blobDownloadURIHttpsInvalid = { .data =
                                                    reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd)),
    .size = strlen(g_testKeystorePwd) + 1 };

static CfBlob g_blobDownloadURIHttpsInvalid2 = { .data = reinterpret_cast<uint8_t *>(
                                                     const_cast<char *>(g_crlDownloadURIHttpsInvalid)),
    .size = strlen(g_crlDownloadURIHttpsInvalid) + 1 };

static CfBlob g_ocspDigest = { .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_digest)),
    .size = strlen(g_digest) + 1 };

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

void CryptoX509CertChainTestPart2::SetUpTestCase()
{
    CfResult ret;

    HcfX509CertChainSpi *certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPem, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainPemSpi = certChainSpi;

    certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataPem163, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainPemSpi163 = certChainSpi;
}

void CryptoX509CertChainTestPart2::TearDownTestCase()
{
    CfObjDestroy(g_certChainPemSpi);
    CfObjDestroy(g_certChainPemSpi163);
}

void CryptoX509CertChainTestPart2::SetUp() {}

void CryptoX509CertChainTestPart2::TearDown() {}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslPolicyTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslPolicyTest001");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    // test ValidatePolicy failed case
    params.policy = (HcfValPolicyType)-1;
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    params.policy = VALIDATION_POLICY_TYPE_SSL;
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfBlob sslHostname = { 0 };
    params.sslHostname = &sslHostname;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_check_host(_, _, _, _, _)).Times(AnyNumber()).WillOnce(Return(0));
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslUseageTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslUseageTest001");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfKuArray kuArray = { 0 };
    kuArray.count = 9;
    kuArray.data = (HcfKeyUsageType *)CfMalloc(kuArray.count * sizeof(HcfKeyUsageType), 0);
    kuArray.data[0] = KEYUSAGE_DIGITAL_SIGNATURE;
    kuArray.data[1] = KEYUSAGE_NON_REPUDIATION;
    kuArray.data[2] = KEYUSAGE_KEY_ENCIPHERMENT;
    kuArray.data[3] = KEYUSAGE_DATA_ENCIPHERMENT;
    kuArray.data[4] = KEYUSAGE_KEY_AGREEMENT;
    kuArray.data[5] = KEYUSAGE_KEY_CERT_SIGN;
    kuArray.data[6] = KEYUSAGE_CRL_SIGN;
    kuArray.data[7] = KEYUSAGE_ENCIPHER_ONLY;
    kuArray.data[8] = KEYUSAGE_DECIPHER_ONLY;

    params.keyUsage = &kuArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    kuArray.data[8] = (HcfKeyUsageType)-1;
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    // test ValidatePolicy failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    X509OpensslMock::SetMockFlag(false);

    CfFree(kuArray.data);
    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslPart2Test001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslPart2Test001");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslCRLLocalTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslCRLLocalTest001");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_new_null())
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_new_null));
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslInvaidCertId, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslInvaidCertId");
    ASSERT_NE(g_certChainPemSpi, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOpArray revChkOpArray = { 0 };
    revChkOpArray.count = 1;
    revChkOpArray.data = (HcfRevChkOption *)CfMalloc(revChkOpArray.count * sizeof(HcfRevChkOption), 0);
    ASSERT_NE(revChkOpArray.data, nullptr);
    revChkOpArray.data[0] = REVOCATION_CHECK_OPTION_PREFER_OCSP;

    HcfRevocationCheckParam rcp;
    rcp.options = &revChkOpArray;
    params.revocationCheckParam = &rcp;

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    // test ValidateOcspLocal failed case
    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    FreeValidateResult(result);

    // test VerifyOcspSinger failed case
    CfBlob resp;
    resp.data = (uint8_t *)(&g_testOcspResponses[0]);
    resp.size = sizeof(g_testOcspResponses);
    rcp.ocspResponses = &resp;

    ret = g_certChainPemSpi->engineValidate(g_certChainPemSpi, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    FreeValidateResult(result);

    FreeTrustAnchorArr(trustAnchorArray);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationLocalTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationLocalTest001");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_PREFER_OCSP };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    // test ValidateOcspLocal failed case
    CfResult ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest001");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam =
        ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI, &g_blobDownloadURI);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    // test ValidateOcspLocal failed case
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest004, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest004");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam =
        ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI, NULL);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    // test ValidateCrlOnline failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_X509_CRL_load_http));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_push(_, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_push));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_new_null())
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_new_null));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest006, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest006");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam =
        ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI, NULL);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    // test GetDpUrl failed case
    CF_LOG_I("ValidateOpensslRevocationOnLineTest - 3");
    DIST_POINT dp = { 0 };
    X509OpensslMock::SetMockFlag(true);
    dp.distpoint = NULL;
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Return(&dp))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);

    CF_LOG_I("ValidateOpensslRevocationOnLineTest - 4");
    DIST_POINT_NAME dpn;
    dpn.type = GEN_URI;
    dp.distpoint = &dpn;
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Return(&dp))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest007, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest007");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam =
        ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI, NULL);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    // test GetDpUrl failed case
    CF_LOG_I("ValidateOpensslRevocationOnLineTest - 5");
    DIST_POINT dp = { 0 };

    DIST_POINT_NAME dpn;
    dpn.type = GEN_URI;

    dp.distpoint = &dpn;
    dp.distpoint->type = 0;
    dp.distpoint->name.fullname = nullptr;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Return(&dp))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    CfResult ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CF_LOG_I("ValidateOpensslRevocationOnLineTest - 6");
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), GENERAL_NAME_get0_value(_, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(NULL));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CF_LOG_I("ValidateOpensslRevocationOnLineTest - 7");
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest008, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest008");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_PREFER_OCSP, REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(
        data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI, &g_blobDownloadURI, &g_inStreamOcspResponderCert);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    // test ValidateOcspLocal failed case
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OCSP_REQUEST_new())
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OCSP_REQUEST_new));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineHttpsTest001, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineHttpsTest001");

    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_PREFER_OCSP, REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]),
        &g_blobDownloadURIHttps, &g_blobDownloadURI, &g_inStreamOcspResponderCert);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get1_ocsp(_))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_X509_get1_ocsp));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);
    X509OpensslMock::SetMockFlag(false);

    // test Unable to parse url.
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OSSL_HTTP_parse_url(_, _, _, _, _, _, _, _, _))
        .WillOnce(Return(0))
        .WillRepeatedly(Invoke(__real_OSSL_HTTP_parse_url));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    FreeValidateResult(result);
    X509OpensslMock::SetMockFlag(false);

    // test Unable to get leafCert.
    CF_LOG_I("ValidateOpensslRevocationOnLineHttpsTest001 - 1");
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Invoke(__real_OPENSSL_sk_value))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    FreeValidateResult(result);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineHttpsTest002, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineHttpsTest002");

    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_PREFER_OCSP, REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]),
        &g_blobDownloadURIHttps, &g_blobDownloadURI, &g_inStreamOcspResponderCert);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    // test GetOCSPUrl failed case
    X509OpensslMock::SetMockFlag(true);
    params.revocationCheckParam->ocspResponderURI->data = NULL;
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get1_ocsp(_)).Times(AnyNumber()).WillOnce(Return(NULL));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    FreeValidateResult(result);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    params.revocationCheckParam->ocspResponderURI = NULL;
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get1_ocsp(_)).Times(AnyNumber()).WillOnce(Return(NULL));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    FreeValidateResult(result);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    params.revocationCheckParam->ocspResponderURI = &g_blobDownloadURIHttpsInvalid;
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get1_ocsp(_)).Times(AnyNumber()).WillOnce(Return(NULL));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    FreeValidateResult(result);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    params.revocationCheckParam->ocspResponderURI = &g_blobDownloadURIHttpsInvalid2;
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get1_ocsp(_)).Times(AnyNumber()).WillOnce(Return(NULL));
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    FreeValidateResult(result);
    X509OpensslMock::SetMockFlag(false);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest009, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest009");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_PREFER_OCSP, REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER,
        REVOCATION_CHECK_OPTION_FALLBACK_LOCAL };
    params.revocationCheckParam =
        ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    CF_LOG_I("ValidateOpensslRevocationOnLineTest009 - 1");
    // test ValidateOcspLocal failed case
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    CF_LOG_I("ValidateOpensslRevocationOnLineTest009 - 2");
    (void)HcfX509CertificateCreate(&g_inStreamOcspResponderCert, &(params.revocationCheckParam->ocspResponderCert));
    ASSERT_NE(params.revocationCheckParam->ocspResponderCert, nullptr);
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    FreeValidateResult(result);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CF_LOG_I("ValidateOpensslRevocationOnLineTest009 - ok");
}

HWTEST_F(CryptoX509CertChainTestPart2, ValidateOpensslRevocationOnLineTest010, TestSize.Level0)
{
    CF_LOG_I("ValidateOpensslRevocationOnLineTest010");
    ASSERT_NE(g_certChainPemSpi163, nullptr);

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(g_inStreamChainDataPemRoot163, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER, REVOCATION_CHECK_OPTION_FALLBACK_LOCAL };
    params.revocationCheckParam =
        ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]), &g_blobDownloadURI);
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    CfResult ret;

    CF_LOG_I("ValidateOpensslRevocationOnLineTest010 - 1");
    // test ValidateOcspLocal failed case
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    CF_LOG_I("ValidateOpensslRevocationOnLineTest010 - 2");
    (void)HcfX509CertificateCreate(&g_inStreamOcspResponderCert, &(params.revocationCheckParam->ocspResponderCert));
    ASSERT_NE(params.revocationCheckParam->ocspResponderCert, nullptr);
    ret = g_certChainPemSpi163->engineValidate(g_certChainPemSpi163, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CF_LOG_I("ValidateOpensslRevocationOnLineTest010 - ok");
}
} // namespace
