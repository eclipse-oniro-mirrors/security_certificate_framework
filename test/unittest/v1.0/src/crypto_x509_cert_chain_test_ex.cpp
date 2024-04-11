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
#include "certificate_openssl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "fwk_class.h"
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

int __real_X509_print(BIO *bp, X509 *x);
BIO *__real_BIO_new(const BIO_METHOD *type);
int __real_i2d_X509_bio(BIO *bp, X509 *x509);

#ifdef __cplusplus
}
#endif

namespace {
class CryptoX509CertChainTestEx : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static HcfCertChain *g_certChainP7b = nullptr;
static HcfX509CertChainSpi *g_certChainP7bSpi = nullptr;

static const char *GetInvalidCertChainClass(void)
{
    return "HcfInvalidCertChain";
}

void CryptoX509CertChainTestEx::SetUpTestCase()
{
    CfResult ret = HcfCertChainCreate(&g_inStreamChainDataP7b, nullptr, &g_certChainP7b);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(g_certChainP7b, nullptr);

    HcfX509CertChainSpi *certChainSpi = nullptr;
    ret = HcfX509CertChainByEncSpiCreate(&g_inStreamChainDataP7b, &certChainSpi);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(certChainSpi, nullptr);
    g_certChainP7bSpi = certChainSpi;
}

void CryptoX509CertChainTestEx::TearDownTestCase()
{
    CfObjDestroy(g_certChainP7b);
    CfObjDestroy(g_certChainP7bSpi);
}

void CryptoX509CertChainTestEx::SetUp() {}

void CryptoX509CertChainTestEx::TearDown() {}

HWTEST_F(CryptoX509CertChainTestEx, ToStringTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertChainTestEx - ToStringTest001");
    ASSERT_NE(g_certChainP7b, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_certChainP7b->toString(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfCertChain certChain;
    certChain.base.getClass = GetInvalidCertChainClass;

    ret = g_certChainP7b->toString(&certChain, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->toString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->toString(g_certChainP7b, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->toString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_BIO_new));
    ret = g_certChainP7b->toString(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_print(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_X509_print));
    ret = g_certChainP7b->toString(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_ctrl(_, _, _, _)).Times(AnyNumber()).WillOnce(Return(0));
    ret = g_certChainP7b->toString(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainTestEx, HashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertChainTestEx - HashCodeTest001");
    ASSERT_NE(g_certChainP7b, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    SetMockFlag(true);
    ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    HcfCertChain certChain;
    certChain.base.getClass = GetInvalidCertChainClass;

    ret = g_certChainP7b->hashCode(&certChain, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->hashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->hashCode(g_certChainP7b, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7b->hashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_BIO_new));
    ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509_bio(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_i2d_X509_bio));
    ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_ctrl(_, _, _, _)).Times(AnyNumber()).WillOnce(Return(0));
    ret = g_certChainP7b->hashCode(g_certChainP7b, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainTestEx, HcfX509CertChainSpiEngineToStringTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainSpiEngineToStringTest001");
    ASSERT_NE(g_certChainP7bSpi, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_certChainP7bSpi->engineToString(g_certChainP7bSpi, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CertChainSpi InvalidCertChainSpi;
    InvalidCertChainSpi.base.getClass = GetInvalidCertChainClass;

    ret = g_certChainP7bSpi->engineToString(&InvalidCertChainSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineToString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineToString(g_certChainP7bSpi, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineToString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertChainTestEx, HcfX509CertChainSpiEngineHashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CertChainSpiEngineHashCodeTest001");
    ASSERT_NE(g_certChainP7bSpi, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_certChainP7bSpi->engineHashCode(g_certChainP7bSpi, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CertChainSpi InvalidCertChainSpi;
    InvalidCertChainSpi.base.getClass = GetInvalidCertChainClass;

    ret = g_certChainP7bSpi->engineHashCode(&InvalidCertChainSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineHashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineHashCode(g_certChainP7bSpi, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_certChainP7bSpi->engineHashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

} // namespace
