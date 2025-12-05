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
using ::testing::DoAll;

#ifdef __cplusplus
extern "C" {
#endif

int __real_BIO_do_connect_retry(BIO *b, int timeout, int retry);
void *__real_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
unsigned long __real_ERR_peek_last_error(void);
X509_CRL *__real_X509_CRL_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);
int __real_OPENSSL_sk_num(const OPENSSL_STACK *st);
void *__real_OPENSSL_sk_value(const OPENSSL_STACK *st, int i);
CfResult __real_CfGetCertIdInfo(STACK_OF(X509) *x509CertChain, const CfBlob *ocspDigest,
    HcfX509TrustAnchor *trustAnchor, OcspCertIdInfo *certIdInfo, int index);
X509 *__real_X509_load_http(const char *url, BIO *bio, BIO *rbio, int timeout);
CfResult __real_ValidateCertDate(X509 *cert, CfBlob *date);
X509_STORE *__real_X509_STORE_new(void);
int __real_X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
X509_STORE_CTX *__real_X509_STORE_CTX_new(void);
int __real_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) * chain);
int __real_X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
CfResult __real_GetIssuerCertFromAllCerts(STACK_OF(X509) *allCerts, X509 *cert, X509 **out);
bool __real_CheckIsSelfSigned(const X509 *cert);
int __real_OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
X509 *__real_X509_dup(X509 *x509);
int __real_X509_check_issued(X509 *issuer, X509 *subject);

void ResetMockFunctionPartOne(void)
{
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        BIO_do_connect_retry(_, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_BIO_do_connect_retry));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_get_ext_d2i(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_STORE_new()).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_STORE_new));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OPENSSL_sk_num(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        OPENSSL_sk_value(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_STORE_add_cert(_, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_STORE_add_cert));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_STORE_CTX_new()).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_STORE_CTX_new));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_STORE_CTX_init(_, _, _, _)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_X509_STORE_CTX_init));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        X509_STORE_CTX_get1_issuer(_, _, _)).Times(AnyNumber()).WillRepeatedly(
        Invoke(__real_X509_STORE_CTX_get1_issuer));
    EXPECT_CALL(X509OpensslMock::GetInstance(),
        CheckIsSelfSigned(_)).Times(AnyNumber()).WillRepeatedly(Invoke(__real_CheckIsSelfSigned));
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

static const char g_crlDownloadURI[] =
    "http://crl3.digicert.com/DigiCertGlobalRootG2.crl";

static CfBlob g_blobDownloadURI = { .size = static_cast<uint32_t>(strlen(g_crlDownloadURI) + 1),
    .data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_crlDownloadURI)) };

const int g_testCaChainValidSize = sizeof(g_testCaChainValid) / sizeof(char);
const CfEncodingBlob g_inCaChain = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCaChainValid)),
    g_testCaChainValidSize, CF_FORMAT_PEM };

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

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest001, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPemWithOcsp = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPemWithOcsp);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemWithOcsp, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE, REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_num(_))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(0));
    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemWithOcsp);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest002, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPemWithOcsp = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPemWithOcsp);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPemWithOcsp, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;

    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268959746));
    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPemWithOcsp->engineValidate(certChainPemWithOcsp, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPemWithOcsp);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest003, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);

    HcfRevChkOption data2[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR,
        REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER, REVOCATION_CHECK_OPTION_ACCESS_NETWORK };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data2, sizeof(data2) / sizeof(data2[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest004, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE,
        REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER};
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillOnce(Return(-1))
         .WillOnce(Return(1))
         .WillRepeatedly(Invoke(__real_BIO_do_connect_retry));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest005, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE};
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillOnce(Return(268435603))
        .WillRepeatedly(Return(268959746));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest006, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_PREFER_OCSP,
        REVOCATION_CHECK_OPTION_ACCESS_NETWORK, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE};
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
         .WillRepeatedly(Return(-1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillOnce(Return(268435603))
        .WillRepeatedly(Return(268959746));
    EXPECT_CALL(X509OpensslMock::GetInstance(), CfGetCertIdInfo(_, _, _, _, _))
        .WillOnce(Return(CF_SUCCESS))
        .WillOnce(Return(CF_ERR_CRYPTO_OPERATION))
        .WillRepeatedly(Invoke(__real_CfGetCertIdInfo));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest007, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest008, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillOnce(Return(268435603))
        .WillRepeatedly(Return(268959746));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest009, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE};
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268959746));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest010, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);
    params.revocationCheckParam->crlDownloadURI = &g_blobDownloadURI;

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest011, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);

    X509_CRL *crl = X509_CRL_new();
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
         .WillOnce(Return(crl))
         .WillRepeatedly(Invoke(__real_X509_CRL_load_http));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ValidateIgnoreNetworkErrorTest012, TestSize.Level0)
{
    HcfX509CertChainSpi *certChainPem = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&g_inCaChain, &certChainPem);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainPem, nullptr);
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;

    HcfX509TrustAnchorArray trustAnchorArray = { 0 };
    BuildAnchorArr(inStream, trustAnchorArray);

    HcfX509CertChainValidateParams params = { 0 };
    params.trustAnchors = &trustAnchorArray;
    HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR, REVOCATION_CHECK_OPTION_ACCESS_NETWORK,
        REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE };
    params.revocationCheckParam = ConstructHcfRevocationCheckParam(data, sizeof(data) / sizeof(data[0]));
    ASSERT_NE(params.revocationCheckParam, nullptr);
    params.revocationCheckParam->crlDownloadURI = &g_blobDownloadURI;

    HcfX509CertChainValidateResult result = { 0 };
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_last_error())
        .WillRepeatedly(Return(268435603));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    FreeValidateResult(result);

    X509_CRL *crl = X509_CRL_new();
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillOnce(Return(nullptr))
        .WillOnce(Return(crl))
        .WillRepeatedly(Invoke(__real_X509_CRL_load_http));
    ret = certChainPem->engineValidate(certChainPem, &params, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);

    FreeValidateResult(result);
    FreeTrustAnchorArr(trustAnchorArray);
    FreeHcfRevocationCheckParam(params.revocationCheckParam);
    CfObjDestroy(certChainPem);
}

HWTEST_F(CryptoX509CertChainTestPart3, ContainsOptionTest001, TestSize.Level0)
{
    bool result = ContainsOption(nullptr, REVOCATION_CHECK_OPTION_ACCESS_NETWORK);
    EXPECT_EQ(result, false);

    HcfRevChkOpArray *options = (HcfRevChkOpArray *)CfMalloc(sizeof(HcfRevChkOpArray), 0);
    ASSERT_NE(options, nullptr);
    options->count = 2;
    options->data = nullptr;
    result = ContainsOption(options, REVOCATION_CHECK_OPTION_ACCESS_NETWORK);
    EXPECT_EQ(result, false);
    CfFree(options);

    HcfRevChkOpArray *options2 = (HcfRevChkOpArray *)CfMalloc(sizeof(HcfRevChkOpArray), 0);
    ASSERT_NE(options2, nullptr);
    options2->count = 2;
    options2->data = (HcfRevChkOption *)CfMalloc(options2->count * sizeof(HcfRevChkOption), 0);
    ASSERT_NE(options2->data, nullptr);
    options2->data[0] = REVOCATION_CHECK_OPTION_ACCESS_NETWORK;
    options2->data[1] = REVOCATION_CHECK_OPTION_PREFER_OCSP;
    result = ContainsOption(options2, REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE);
    EXPECT_EQ(result, false);

    CfFree(options2->data);
    CfFree(options2);
}

static void BuildCertCRLCollectionsDataEx(
    const CfEncodingBlob *certInStream, const CfEncodingBlob *certInStream2, HcfX509CertChainValidateParams *params)
{
    if (certInStream == nullptr || params == nullptr) {
        return;
    }
    HcfCertCRLCollectionArray *certCRLCollections =
        (HcfCertCRLCollectionArray *)CfMalloc(sizeof(HcfCertCRLCollectionArray), 0);
    ASSERT_NE(certCRLCollections, nullptr);
    BuildCollectionArrEx(certInStream, certInStream2, *certCRLCollections);

    params->certCRLCollections = certCRLCollections;
}

static void BuildCertCRLCollectionsData(
    const CfEncodingBlob *certInStream, const CfEncodingBlob *crlInStream, HcfX509CertChainValidateParams *params)
{
    if (certInStream == nullptr || params == nullptr) {
        return;
    }
    HcfCertCRLCollectionArray *certCRLCollections =
        (HcfCertCRLCollectionArray *)CfMalloc(sizeof(HcfCertCRLCollectionArray), 0);
    ASSERT_NE(certCRLCollections, nullptr);
    BuildCollectionArr(certInStream, crlInStream, *certCRLCollections);

    params->certCRLCollections = certCRLCollections;
}

static void BuildTrustAnchorsData(const CfEncodingBlob *certInStream, HcfX509CertChainValidateParams *params)
{
    if (certInStream == nullptr || params == nullptr) {
        return;
    }
    HcfX509TrustAnchorArray *trustAnchorArray =
        (HcfX509TrustAnchorArray *)CfMalloc(sizeof(HcfX509TrustAnchorArray), 0);
    ASSERT_NE(trustAnchorArray, nullptr);
    BuildAnchorArr(*certInStream, *trustAnchorArray);

    params->trustAnchors = trustAnchorArray;
}

static void FreeX509CertMatchParamsData(HcfX509CertChainValidateParams *params)
{
    if (params == nullptr) {
        return;
    }

    if (params->trustAnchors != nullptr) {
        FreeTrustAnchorArr(*(params->trustAnchors));
        CfFree(params->trustAnchors);
        params->trustAnchors = nullptr;
    }

    if (params->certCRLCollections != nullptr) {
        FreeCertCrlCollectionArr(*(params->certCRLCollections));
        CfFree(params->certCRLCollections);
        params->certCRLCollections = nullptr;
    }
}

static X509 *LoadX509FromCrtData(const char *data, size_t dataLen)
{
    BIO *bio = BIO_new_mem_buf(reinterpret_cast<const void *>(data), static_cast<int>(dataLen));
    if (bio == nullptr) {
        return nullptr;
    }
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return cert;
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest001, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = false;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert = LoadX509FromCrtData(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillRepeatedly(Return(downloadCert));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_NE(spi, nullptr);
    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(spi);

    inParams.maxlength = 1;
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    inParams.maxlength = 4;
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    inParams.validateParameters.allowDownloadIntermediateCa = false;
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest002, TestSize.Level0)
{
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &pCertChainValidateParams);

    pCertChainValidateParams.allowDownloadIntermediateCa = true;
    pCertChainValidateParams.trustSystemCa = false;
    HcfX509CertChainValidateResult result = { 0 };

    X509 *downloadCert = LoadX509FromCrtData(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    X509OpensslMock::SetMockFlag(false);
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    pCertChainValidateParams.allowDownloadIntermediateCa = false;
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    FreeValidateResult(result);
    X509_free(downloadCert);
    FreeX509CertMatchParamsData(&pCertChainValidateParams);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest003, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCert7Level) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = false;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);
    X509 *downloadCert5 = LoadX509FromCrtData(g_testCa5Cert7Level, strlen(g_testCa5Cert7Level) + 1);
    X509 *downloadCert4 = LoadX509FromCrtData(g_testCa4Cert7Level, strlen(g_testCa4Cert7Level) + 1);
    X509 *downloadCert3 = LoadX509FromCrtData(g_testCa3Cert7Level, strlen(g_testCa3Cert7Level) + 1);
    X509 *downloadCert2 = LoadX509FromCrtData(g_testCa2Cert7Level, strlen(g_testCa2Cert7Level) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillOnce(Return(downloadCert5))
        .WillOnce(Return(downloadCert4))
        .WillOnce(Return(downloadCert3))
        .WillOnce(Return(downloadCert2))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest004, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCert7Level) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_new())
        .WillRepeatedly(Return(nullptr));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest005, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;
    CfEncodingBlob inStream2 = { 0 };
    inStream2.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCert7Level));
    inStream2.encodingFormat = CF_FORMAT_PEM;
    inStream2.len = strlen(g_testRootCert7Level) + 1;

    BuildCertCRLCollectionsDataEx(&inStream, &inStream2, &inParams.validateParameters);
    BuildTrustAnchorsData(&inStream2, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_add_cert(_, _))
        .WillRepeatedly(Return(0));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest006, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCert7Level) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_new())
        .WillRepeatedly(Return(nullptr));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest007, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCert7Level) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_init(_, _, _, _))
        .WillRepeatedly(Return(0));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest008, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCert7Level) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get1_issuer(_, _, _))
        .WillRepeatedly(Return(-1));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest009, TestSize.Level0)
{
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCert7Level) + 1;
    BuildTrustAnchorsData(&inStream, &pCertChainValidateParams);

    pCertChainValidateParams.allowDownloadIntermediateCa = true;
    pCertChainValidateParams.trustSystemCa = true;
    HcfX509CertChainValidateResult result = { 0 };

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);
    X509 *downloadCert5 = LoadX509FromCrtData(g_testCa5Cert7Level, strlen(g_testCa5Cert7Level) + 1);
    X509 *downloadCert4 = LoadX509FromCrtData(g_testCa4Cert7Level, strlen(g_testCa4Cert7Level) + 1);
    X509 *downloadCert3 = LoadX509FromCrtData(g_testCa3Cert7Level, strlen(g_testCa3Cert7Level) + 1);
    X509 *downloadCert2 = LoadX509FromCrtData(g_testCa2Cert7Level, strlen(g_testCa2Cert7Level) + 1);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillOnce(Return(downloadCert5))
        .WillOnce(Return(downloadCert4))
        .WillOnce(Return(downloadCert3))
        .WillOnce(Return(downloadCert2))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509_free(downloadCert6);
    X509_free(downloadCert5);
    X509_free(downloadCert4);
    X509_free(downloadCert3);
    X509_free(downloadCert2);
    FreeValidateResult(result);
    FreeX509CertMatchParamsData(&pCertChainValidateParams);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest010, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_INVALID_PARAMS);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .WillOnce(Invoke(__real_X509_get_ext_d2i))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest011, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest012, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert = LoadX509FromCrtData(g_testLeafCertValid, strlen(g_testLeafCertValid) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillRepeatedly(Return(downloadCert));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    CfObjDestroy(spi);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest013, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCert7Level) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert = LoadX509FromCrtData(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest014, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testDownloadCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testDownloadCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = false;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_NE(spi, nullptr);
    CfObjDestroy(spi);
    
    inParams.validateParameters.allowDownloadIntermediateCa = false;
    inParams.validateParameters.trustSystemCa = true;
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_NE(spi, nullptr);

    CfObjDestroy(spi);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest015, TestSize.Level0)
{
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;
    HcfX509CertChainSpi *certChainSpi = nullptr;
    CfResult ret = HcfX509CertChainByEncSpiCreate(&inStream, &certChainSpi);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testDownloadCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testDownloadCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &pCertChainValidateParams);

    pCertChainValidateParams.allowDownloadIntermediateCa = true;
    pCertChainValidateParams.trustSystemCa = true;
    HcfX509CertChainValidateResult result = { 0 };
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    EXPECT_EQ(ret, CF_SUCCESS);
    FreeValidateResult(result);

    pCertChainValidateParams.allowDownloadIntermediateCa = false;
    pCertChainValidateParams.trustSystemCa = false;
    ret = certChainSpi->engineValidate(certChainSpi, &pCertChainValidateParams, &result);
    EXPECT_EQ(ret, CF_SUCCESS);

    FreeValidateResult(result);
    FreeX509CertMatchParamsData(&pCertChainValidateParams);
    CfObjDestroy(certChainSpi);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest016, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafNoCaIssuer));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafNoCaIssuer) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest017, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = false;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert = LoadX509FromCrtData(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillRepeatedly(Return(downloadCert));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ValidateCertDate(_, _))
        .WillOnce(Return(CF_ERR_CRYPTO_OPERATION))
        .WillRepeatedly(Invoke(__real_ValidateCertDate));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest018, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = 2;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCert7Level) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);

    inParams.maxlength = 2;
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_PARAMETER_CHECK);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest019, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;

    BuildCertCRLCollectionsData(&inStream, NULL, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert = LoadX509FromCrtData(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillRepeatedly(Return(downloadCert));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_push(_, _))
        .WillOnce(__real_OPENSSL_sk_push)
        .WillOnce(__real_OPENSSL_sk_push)
        .WillOnce(__real_OPENSSL_sk_push)
        .WillOnce(__real_OPENSSL_sk_push)
        .WillOnce(__real_OPENSSL_sk_push)
        .WillOnce(Return(0))
        .WillRepeatedly(__real_OPENSSL_sk_push);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get1_issuer(_, _, _))
        .WillRepeatedly(Return(1));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
    FreeTrustAnchorData(nullptr);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest020, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;
    CfEncodingBlob inStream2 = { 0 };
    inStream2.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream2.encodingFormat = CF_FORMAT_PEM;
    inStream2.len = strlen(g_testRootCertValid) + 1;

    BuildCertCRLCollectionsDataEx(&inStream, &inStream2, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = false;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert = LoadX509FromCrtData(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillRepeatedly(Return(downloadCert));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_NE(spi, nullptr);
    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(spi);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest021, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;
    CfEncodingBlob inStream2 = { 0 };
    inStream2.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream2.encodingFormat = CF_FORMAT_PEM;
    inStream2.len = strlen(g_testRootCertValid) + 1;

    BuildCertCRLCollectionsDataEx(&inStream, &inStream2, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = false;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert = LoadX509FromCrtData(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillRepeatedly(Return(downloadCert));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_dup(_))
        .WillOnce(Invoke(__real_X509_dup))
        .WillOnce(Invoke(__real_X509_dup))
        .WillOnce(Invoke(__real_X509_dup))
        .WillOnce(Invoke(__real_X509_dup))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_dup));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest022, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCertValid) + 1;
    CfEncodingBlob inStream2 = { 0 };
    inStream2.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream2.encodingFormat = CF_FORMAT_PEM;
    inStream2.len = strlen(g_testRootCertValid) + 1;

    BuildCertCRLCollectionsDataEx(&inStream, &inStream2, &inParams.validateParameters);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testRootCertValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testRootCertValid) + 1;
    BuildTrustAnchorsData(&inStream, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = false;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert = LoadX509FromCrtData(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillRepeatedly(Return(downloadCert));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_push(_, _))
        .WillOnce(Invoke(__real_OPENSSL_sk_push))
        .WillOnce(Invoke(__real_OPENSSL_sk_push))
        .WillOnce(Invoke(__real_OPENSSL_sk_push))
        .WillOnce(Invoke(__real_OPENSSL_sk_push))
        .WillOnce(Invoke(__real_OPENSSL_sk_push))
        .WillOnce(Invoke(__real_OPENSSL_sk_push))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_push));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest023, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;
    CfEncodingBlob inStream2 = { 0 };
    inStream2.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCa5Cert7Level));
    inStream2.encodingFormat = CF_FORMAT_PEM;
    inStream2.len = strlen(g_testCa5Cert7Level) + 1;

    BuildCertCRLCollectionsDataEx(&inStream, &inStream2, &inParams.validateParameters);
    inStream2.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCa4Cert7Level));
    inStream2.encodingFormat = CF_FORMAT_PEM;
    inStream2.len = strlen(g_testCa4Cert7Level) + 1;

    BuildTrustAnchorsData(&inStream2, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_NE(spi, nullptr);
    X509OpensslMock::SetMockFlag(false);
    CfObjDestroy(spi);

    FreeX509CertMatchParamsData(&inParams.validateParameters);
}

HWTEST_F(CryptoX509CertChainTestPart3, HcfAllowDownloadIntermediateCaTest024, TestSize.Level0)
{
    HcfX509CertChainBuildParameters inParams;
    memset_s(&inParams, sizeof(HcfX509CertChainBuildParameters), 0, sizeof(HcfX509CertChainBuildParameters));
    HcfX509CertChainSpi *spi = nullptr;

    CfResult result;
    inParams.maxlength = -1;

    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testLeafCert7Level));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testLeafCert7Level) + 1;
    CfEncodingBlob inStream2 = { 0 };
    inStream2.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCa5Cert7Level));
    inStream2.encodingFormat = CF_FORMAT_PEM;
    inStream2.len = strlen(g_testCa5Cert7Level) + 1;

    BuildCertCRLCollectionsDataEx(&inStream, &inStream2, &inParams.validateParameters);
    inStream2.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCa4Cert7Level));
    inStream2.encodingFormat = CF_FORMAT_PEM;
    inStream2.len = strlen(g_testCa4Cert7Level) + 1;

    BuildTrustAnchorsData(&inStream2, &inParams.validateParameters);

    inParams.validateParameters.allowDownloadIntermediateCa = true;
    inParams.validateParameters.trustSystemCa = true;
    inParams.certMatchParameters.minPathLenConstraint = -1;

    X509 *downloadCert6 = LoadX509FromCrtData(g_testCa6Cert7Level, strlen(g_testCa6Cert7Level) + 1);
    X509OpensslMock::SetMockFlag(true);
    ResetMockFunction();
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadCert6))
        .WillRepeatedly(Invoke(__real_X509_load_http));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_check_issued(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_X509_check_issued));
    result = HcfX509CertChainByParamsSpiCreate(&inParams, &spi);
    EXPECT_EQ(result, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    X509OpensslMock::SetMockFlag(false);

    EXPECT_EQ(spi, nullptr);
    FreeX509CertMatchParamsData(&inParams.validateParameters);
}
} // namespace
