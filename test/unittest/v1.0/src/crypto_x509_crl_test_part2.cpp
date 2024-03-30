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
#include "cf_log.h"
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
static uint8_t g_testSn[] = { 0x03, 0xe8 };
HcfX509Crl *g_x509Crl = nullptr;
HcfX509CrlEntry *g_crlEntry = nullptr;
HcfX509CrlSpi *g_crlSpiObj = nullptr;

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
    CfResult ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(x509Crl, nullptr);
    g_x509Crl = x509Crl;

    CfBlob testSnBlob = { 2, g_testSn };
    ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &g_crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(g_crlEntry, nullptr);

    ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &g_crlSpiObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(g_crlSpiObj, nullptr);
}

void CryptoX509CrlTestPart2::TearDownTestCase()
{
    if (g_x509Crl != nullptr) {
        CfObjDestroy(g_x509Crl);
        g_x509Crl = nullptr;
    }

    if (g_crlEntry != nullptr) {
        CfObjDestroy(g_crlEntry);
        g_crlEntry = nullptr;
    }

    if (g_crlSpiObj != nullptr) {
        CfObjDestroy(g_crlSpiObj);
        g_crlSpiObj = nullptr;
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
    out1.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    out1.size = g_testCrlSubAndIssNameDerDataSize;

    CfBlobArray cfBlobArr;
    CfBlob cfb[2] = { out1, out1 };
    cfBlobArr.data = cfb;
    cfBlobArr.count = 2;

    HcfX509CrlMatchParams matchParams;
    matchParams.issuer = &cfBlobArr;
    bool bResult = true;
    CfResult ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
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
    EXPECT_EQ((out1.size >= 2), true);
    out1.data[1] = out1.data[1] + 1; // modify to a different value.

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

    CfFree(out1.data);
    CfObjDestroy(x509Crl);
}

/* issuer->count is 0 and outTmpSelf.size is not 0 */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest011, TestSize.Level0)
{
    // get issuer name
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out1 = { 0, nullptr };
    out1.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    out1.size = g_testCrlSubAndIssNameDerDataSize;

    CfBlobArray cfBlobArr;
    CfBlob cfb[2] = { out1, out1 };
    cfBlobArr.data = cfb;
    cfBlobArr.count = 0;

    HcfX509CrlMatchParams matchParams;
    matchParams.issuer = &cfBlobArr;
    bool bResult = true;
    CfResult ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* issuer->data[0].data is nullptr */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest012, TestSize.Level0)
{
    // get issuer name
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out1 = { 0, nullptr };
    CfBlob out2 = { 0, nullptr };
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
    CfResult ret = g_x509Crl->match(g_x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

/* i == issuer->count - 1 */
HWTEST_F(CryptoX509CrlTestPart2, MatchX509CRLTest013, TestSize.Level0)
{
    // get issuer name
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out1 = { 0, nullptr };
    out1.data = (uint8_t *)(&g_testCrlSubAndIssNameDerData[0]);
    out1.size = g_testCrlSubAndIssNameDerDataSize;

    CfBlobArray cfBlobArr;
    CfBlob cfb[2] = { out1, out1 };
    cfBlobArr.data = cfb;
    cfBlobArr.count = 2;

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_crlWithoutExtPemInStream, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlMatchParams matchParams;
    matchParams.issuer = &cfBlobArr;
    bool bResult = true;
    ret = x509Crl->match(x509Crl, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfObjDestroy(x509Crl);
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

HWTEST_F(CryptoX509CrlTestPart2, CrlToStringTest001, TestSize.Level0)
{
    CF_LOG_I("CrlToStringTest001");
    ASSERT_NE(g_x509Crl, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509Crl->toString(g_x509Crl, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509Crl invalidCrl;
    invalidCrl.base.base.getClass = GetInvalidCrlClass;

    ret = g_x509Crl->toString(&invalidCrl, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Crl->toString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Crl->toString(g_x509Crl, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Crl->toString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CrlTestPart2, CrlHashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("CrlHashCodeTest001");
    ASSERT_NE(g_x509Crl, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509Crl->hashCode(g_x509Crl, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509Crl invalidCrl;
    invalidCrl.base.base.getClass = GetInvalidCrlClass;

    ret = g_x509Crl->hashCode(&invalidCrl, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Crl->hashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Crl->hashCode(g_x509Crl, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Crl->hashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CrlTestPart2, CrlGetExtensionsObjectTest001, TestSize.Level0)
{
    CF_LOG_I("CrlGetExtensionsObjectTest001");
    ASSERT_NE(g_x509Crl, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509Crl->getExtensionsObject(g_x509Crl, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509Crl invalidCrl;
    invalidCrl.base.base.getClass = GetInvalidCrlClass;

    ret = g_x509Crl->getExtensionsObject(&invalidCrl, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Crl->getExtensionsObject(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Crl->getExtensionsObject(g_x509Crl, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509Crl->getExtensionsObject(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CrlTestPart2, CrlEntryToStringTest001, TestSize.Level0)
{
    CF_LOG_I("CrlEntryToStringTest001");
    ASSERT_NE(g_crlEntry, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_crlEntry->toString(g_crlEntry, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CrlEntry invalidCrlEntry;
    HcfX509CRLEntryOpensslImpl *imp = (HcfX509CRLEntryOpensslImpl*)&invalidCrlEntry;
    imp->base.base.getClass = GetInvalidCrlClass;

    ret = g_crlEntry->toString(&invalidCrlEntry, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlEntry->toString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlEntry->toString(g_crlEntry, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlEntry->toString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CrlTestPart2, CrlEntryHashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("CrlEntryHashCodeTest001");
    ASSERT_NE(g_crlEntry, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_crlEntry->hashCode(g_crlEntry, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CrlEntry invalidCrlEntry;
    HcfX509CRLEntryOpensslImpl *imp = (HcfX509CRLEntryOpensslImpl*)&invalidCrlEntry;
    imp->base.base.getClass = GetInvalidCrlClass;

    ret = g_crlEntry->hashCode(&invalidCrlEntry, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlEntry->hashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlEntry->hashCode(g_crlEntry, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlEntry->hashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CrlTestPart2, CrlEntryGetExtensionsObjectTest001, TestSize.Level0)
{
    CF_LOG_I("CrlEntryGetExtensionsObjectTest001");
    ASSERT_NE(g_crlEntry, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_crlEntry->getExtensionsObject(g_crlEntry, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CrlEntry invalidCrlEntry;
    HcfX509CRLEntryOpensslImpl *imp = (HcfX509CRLEntryOpensslImpl*)&invalidCrlEntry;
    imp->base.base.getClass = GetInvalidCrlClass;

    ret = g_crlEntry->getExtensionsObject(&invalidCrlEntry, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlEntry->getExtensionsObject(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlEntry->getExtensionsObject(g_crlEntry, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlEntry->getExtensionsObject(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CrlTestPart2, HcfX509CrlSpiEngineToStringTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CrlSpiEngineToStringTest001");
    ASSERT_NE(g_crlSpiObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_crlSpiObj->engineToString(g_crlSpiObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CrlSpi invalidCrlSpi;
    invalidCrlSpi.base.getClass = GetInvalidCrlClass;

    ret = g_crlSpiObj->engineToString(&invalidCrlSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlSpiObj->engineToString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlSpiObj->engineToString(g_crlSpiObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlSpiObj->engineToString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CrlTestPart2, HcfX509CrlSpiEngineHashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CrlSpiEngineHashCodeTest001");
    ASSERT_NE(g_crlSpiObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_crlSpiObj->engineHashCode(g_crlSpiObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CrlSpi invalidCrlSpi;
    invalidCrlSpi.base.getClass = GetInvalidCrlClass;

    ret = g_crlSpiObj->engineHashCode(&invalidCrlSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlSpiObj->engineHashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlSpiObj->engineHashCode(g_crlSpiObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlSpiObj->engineHashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CrlTestPart2, HcfX509CrlSpiEngineGetExtensionsObjectTest001, TestSize.Level0)
{
    CF_LOG_I("HcfX509CrlSpiEngineGetExtensionsObjectTest001");
    ASSERT_NE(g_crlSpiObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_crlSpiObj->engineGetExtensionsObject(g_crlSpiObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509CrlSpi invalidCrlSpi;
    invalidCrlSpi.base.getClass = GetInvalidCrlClass;

    ret = g_crlSpiObj->engineGetExtensionsObject(&invalidCrlSpi, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlSpiObj->engineGetExtensionsObject(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlSpiObj->engineGetExtensionsObject(g_crlSpiObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_crlSpiObj->engineGetExtensionsObject(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

} // namespace
