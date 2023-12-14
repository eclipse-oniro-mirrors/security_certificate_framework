/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <openssl/x509.h>

#include "asy_key_generator.h"
#include "certificate_openssl_class.h"
#include "cf_memory.h"
#include "cipher.h"
#include "crypto_x509_test_common.h"
#include "key_pair.h"
#include "memory_mock.h"
#include "securec.h"
#include "x509_crl.h"
#include "x509_crl_entry_openssl.h"
#include "x509_crl_match_parameters.h"
#include "x509_crl_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
HcfX509Crl *g_x509Crl = nullptr;

class CryptoX509CrlTestPart2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoX509CrlTestPart2::SetUpTestCase()
{
    HcfX509Crl *x509Crl = nullptr;
    int32_t ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(x509Crl, nullptr);
    g_x509Crl = x509Crl;
}

void CryptoX509CrlTestPart2::TearDownTestCase()
{
    if (g_x509Crl != nullptr) {
        CfObjDestroy(g_x509Crl);
        g_x509Crl = nullptr;
    }
}
void CryptoX509CrlTestPart2::SetUp() {}
void CryptoX509CrlTestPart2::TearDown() {}

static const char *GetInvalidCrlClass(void)
{
    return "INVALID_CRL_CLASS";
}

/* self point is nullptr */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest001, TestSize.Level0)
{
    bool bResult = true;
    HcfX509CrlMatchParams matchParams;
    CfResult ret = g_x509Crl->match(nullptr, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* x509Cert point is nullptr */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    bool bResult = true;
    CfResult ret = g_x509Crl->match(g_x509Crl, nullptr, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* out point is nullptr */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest003, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlMatchParams matchParams;
    CfResult ret = g_x509Crl->match(g_x509Crl, &matchParams, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* Get Invalid Crl Class */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest004, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlMatchParams matchParams;
    HcfX509Crl invalidCrl;
    invalidCrl.base.base.getClass = GetInvalidCrlClass;
    bool bResult = true;
    CfResult ret = g_x509Crl->match(&invalidCrl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* x509Cert is nullptr */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest005, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlMatchParams matchParams;
    matchParams.x509Cert = nullptr;
    bool bResult = true;
    CfResult ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/* self x509Cert is not equal to x509Crl */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest006, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStreamCert = { nullptr, 0, CF_FORMAT_PEM };
    inStreamCert.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testErrorCert));
    inStreamCert.encodingFormat = CF_FORMAT_PEM;
    inStreamCert.len = strlen(g_testErrorCert) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlMatchParams matchParams;
    matchParams.x509Cert = &(x509Cert->base);
    bool bResult = true;
    ret = x509Crl->match(x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    CfObjDestroy(x509Cert);
    CfObjDestroy(x509Crl);
}

/* self x509Cert is equal to x509Crl  */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest007, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    HcfX509CrlMatchParams matchParams;
    matchParams.x509Cert = &(x509Cert->base);
    bool bResult = true;
    ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
    CfObjDestroy(x509Cert);
}

/* issuer is nullptr */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest008, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlMatchParams matchParams;
    matchParams.issuer = nullptr;
    bool bResult = true;
    CfResult ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/* self issuer is equal to x509Crl */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest009, TestSize.Level0)
{
    // get issuer name
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out1 = { 0, nullptr };
    CfResult ret = g_x509Crl->getIssuerName(g_x509Crl, &out1);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfFree(out1.data);
    out1.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    out1.size = g_testCrlSubAndIssNameDerDataSize;

    CfBlobArray cfBlobArr;
    CfBlob cfb[2] = { out1, out1 };
    cfBlobArr.data = cfb;
    cfBlobArr.count = 2;

    HcfX509CrlMatchParams matchParams;
    matchParams.issuer = &cfBlobArr;
    bool bResult = true;
    ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
}

/* self issuer is not equal to x509Crl */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest010, TestSize.Level0)
{
    // get issuer name
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out1 = { 0, nullptr };
    CfResult ret = g_x509Crl->getIssuerName(g_x509Crl, &out1);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfFree(out1.data);

    CfBlobArray cfBlobArr;
    CfBlob cfb[2] = { out1, out1 };
    cfBlobArr.data = cfb;
    cfBlobArr.count = 2;

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlMatchParams matchParams;
    matchParams.issuer = &cfBlobArr;
    bool bResult = true;
    ret = x509Crl->match(x509Crl, &matchParams, &bResult);
    EXPECT_NE(ret, CF_SUCCESS);
}

/* issuer->count is 0 and outTmpSelf.size is not 0 */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest011, TestSize.Level0)
{
    // get issuer name
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out1 = { 0, nullptr };
    CfResult ret = g_x509Crl->getIssuerName(g_x509Crl, &out1);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfFree(out1.data);
    out1.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    out1.size = g_testCrlSubAndIssNameDerDataSize;

    CfBlobArray cfBlobArr;
    CfBlob cfb[2] = { out1, out1 };
    cfBlobArr.data = cfb;
    cfBlobArr.count = 0;

    HcfX509CrlMatchParams matchParams;
    matchParams.issuer = &cfBlobArr;
    bool bResult = true;
    ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* issuer->data[0].data is nullptr */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest012, TestSize.Level0)
{
    // get issuer name
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out1 = { 0, nullptr };
    CfBlob out2 = { 0, nullptr };
    CfResult ret = g_x509Crl->getIssuerName(g_x509Crl, &out1);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfFree(out1.data);
    ret = g_x509Crl->getIssuerName(g_x509Crl, &out2);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfFree(out2.data);
    out1.data = nullptr;
    out1.size = g_testCrlSubAndIssNameDerDataSize;
    out2.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    out2.size = g_testCrlSubAndIssNameDerDataSize;

    CfBlobArray cfBlobArr;
    CfBlob cfb[2] = { out1, out2 };
    cfBlobArr.data = cfb;
    cfBlobArr.count = 2;

    HcfX509CrlMatchParams matchParams;
    matchParams.issuer = &cfBlobArr;
    bool bResult = true;
    ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* i == issuer->count - 1 */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest013, TestSize.Level0)
{
    // get issuer name
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out1 = { 0, nullptr };
    CfResult ret = g_x509Crl->getIssuerName(g_x509Crl, &out1);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfFree(out1.data);
    out1.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    out1.size = g_testCrlSubAndIssNameDerDataSize;

    CfBlobArray cfBlobArr;
    CfBlob cfb[2] = { out1, out1 };
    cfBlobArr.data = cfb;
    cfBlobArr.count = 2;

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_crlWithoutExtPemInStream, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlMatchParams matchParams;
    matchParams.issuer = &cfBlobArr;
    bool bResult = true;
    ret = x509Crl->match(x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
}

/* match all params */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest014, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // get issuer name
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out1 = { 0, nullptr };
    ret = g_x509Crl->getIssuerName(g_x509Crl, &out1);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfFree(out1.data);
    out1.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    out1.size = g_testCrlSubAndIssNameDerDataSize;

    CfBlobArray cfBlobArr;
    CfBlob cfb[2] = { out1, out1 };
    cfBlobArr.data = cfb;
    cfBlobArr.count = 2;

    HcfX509CrlMatchParams matchParams;
    matchParams.x509Cert = &(x509Cert->base);
    matchParams.issuer = &cfBlobArr;
    bool bResult = true;
    ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);
    CfObjDestroy(x509Cert);
}
} // namespace
