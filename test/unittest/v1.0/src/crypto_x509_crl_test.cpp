/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "cf_log.h"
#include "cf_memory.h"
#include "cipher.h"
#include "crypto_x509_test_common.h"
#include "fwk_class.h"
#include "key_pair.h"
#include "memory_mock.h"
#include "securec.h"
#include "x509_crl.h"
#include "x509_crl_entry_openssl.h"
#include "x509_crl_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
HcfX509Crl *g_x509Crl = nullptr;
uint8_t g_testSn[] = { 0x03, 0xe8 };

class CryptoX509CrlTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoX509CrlTest::SetUpTestCase()
{
    HcfX509Crl *x509Crl = nullptr;
    int32_t ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(x509Crl, nullptr);
    g_x509Crl = x509Crl;
}

void CryptoX509CrlTest::TearDownTestCase()
{
    if (g_x509Crl != nullptr) {
        CfObjDestroy(g_x509Crl);
        g_x509Crl = nullptr;
    }
}
void CryptoX509CrlTest::SetUp() {}
void CryptoX509CrlTest::TearDown() {}

// Begin test crl create, test crl create PEM true
HWTEST_F(CryptoX509CrlTest, X509CrlTest001, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);
    CfObjDestroy(x509Crl);
}

// Test crl create DER true
HWTEST_F(CryptoX509CrlTest, X509CrlTest002, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);
    CfObjDestroy(x509Crl);
}

// Test crl create error | encodingFormat
HWTEST_F(CryptoX509CrlTest, X509CrlTest003, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfEncodingBlob inStreamCrl = { nullptr, 0, CF_FORMAT_PEM };
    inStreamCrl.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCrl));
    inStreamCrl.encodingFormat = CF_FORMAT_DER;
    inStreamCrl.len = strlen(g_testCrl) + 1;
    CfResult ret = HcfX509CrlCreate(&inStreamCrl, &x509Crl);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Crl, nullptr);
}

// Test crl create error | Crl data
HWTEST_F(CryptoX509CrlTest, X509CrlTest004, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfEncodingBlob inStreamCrl = { nullptr, 0, CF_FORMAT_PEM };
    inStreamCrl.data = nullptr;
    inStreamCrl.encodingFormat = CF_FORMAT_PEM;
    inStreamCrl.len = strlen(g_testCrl) + 1;
    CfResult ret = HcfX509CrlCreate(&inStreamCrl, &x509Crl);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Crl, nullptr);
}

// Test crl create error | Crl len
HWTEST_F(CryptoX509CrlTest, X509CrlTest005, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfEncodingBlob inStreamCrl = { nullptr, 0, CF_FORMAT_PEM };
    inStreamCrl.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCrl));
    inStreamCrl.encodingFormat = CF_FORMAT_PEM;
    inStreamCrl.len = 0;
    CfResult ret = HcfX509CrlCreate(&inStreamCrl, &x509Crl);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Crl, nullptr);
}

// Test crl create error | Crl nullptr
HWTEST_F(CryptoX509CrlTest, X509CrlTest006, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    CfEncodingBlob *inStreamCrl = nullptr;
    CfResult ret = HcfX509CrlCreate(inStreamCrl, &x509Crl);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(x509Crl, nullptr);
}

// Begin test crl isRevoked, test crl isRevoked true
HWTEST_F(CryptoX509CrlTest, X509CrlTest011, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    bool resIsRevoked =
        x509Crl->base.isRevoked(reinterpret_cast<HcfCrl *>(x509Crl), reinterpret_cast<HcfCertificate *>(x509Cert));
    EXPECT_EQ(resIsRevoked, true);
    CfObjDestroy(x509Crl);
    CfObjDestroy(x509Cert);
}

// Test crl isRevoked error | crl null
HWTEST_F(CryptoX509CrlTest, X509CrlTest012, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    bool resIsRevoked = g_x509Crl->base.isRevoked(nullptr, reinterpret_cast<HcfCertificate *>(x509Cert));
    EXPECT_EQ(resIsRevoked, false);
    CfObjDestroy(x509Cert);
}

// Test crl isRevoked error | x509Cert null
HWTEST_F(CryptoX509CrlTest, X509CrlTest013, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    bool resIsRevoked = x509Crl->base.isRevoked(reinterpret_cast<HcfCrl *>(x509Crl), nullptr);
    EXPECT_EQ(resIsRevoked, false);
    CfObjDestroy(x509Crl);
}

// Test crl isRevoked - der
HWTEST_F(CryptoX509CrlTest, X509CrlTest014, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_crlDerInStream, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    bool resIsRevoked =
        x509Crl->base.isRevoked(reinterpret_cast<HcfCrl *>(x509Crl), reinterpret_cast<HcfCertificate *>(x509Cert));
    EXPECT_EQ(resIsRevoked, true);
    CfObjDestroy(x509Cert);
    CfObjDestroy(x509Crl);
}

// Test crl isRevoked error | x509Crl error
HWTEST_F(CryptoX509CrlTest, X509CrlTest015, TestSize.Level0)
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

    bool resIsRevoked =
        x509Crl->base.isRevoked(reinterpret_cast<HcfCrl *>(x509Crl), reinterpret_cast<HcfCertificate *>(x509Cert));
    EXPECT_EQ(resIsRevoked, false);
    CfObjDestroy(x509Cert);
    CfObjDestroy(x509Crl);
}

// Test crl GetType true
HWTEST_F(CryptoX509CrlTest, X509CrlTest021, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    const char *resStr = x509Crl->base.getType(reinterpret_cast<HcfCrl *>(x509Crl));
    EXPECT_STREQ(resStr, "X509");
    CfObjDestroy(x509Crl);
}

// Test crl GetType error
HWTEST_F(CryptoX509CrlTest, X509CrlTest022, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    const char *resStr = x509Crl->base.getType(nullptr);
    EXPECT_EQ(resStr, nullptr);
    CfObjDestroy(x509Crl);
}

// Test crl getEncoded DER true
HWTEST_F(CryptoX509CrlTest, X509CrlTest031, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfEncodingBlob inStreamInput = { nullptr, 0, CF_FORMAT_PEM };
    CfResult ret = g_x509Crl->getEncoded(g_x509Crl, &inStreamInput);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfX509Crl *crl2 = nullptr;
    ret = HcfX509CrlCreate(&inStreamInput, &crl2);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crl2, nullptr);
    CfObjDestroy(crl2);
    CfFree(inStreamInput.data);
}

// Test crl getEncoded PEM true
HWTEST_F(CryptoX509CrlTest, X509CrlTest032, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    CfEncodingBlob inStreamInput = { nullptr, 0, CF_FORMAT_PEM };
    ret = x509Crl->getEncoded(x509Crl, &inStreamInput);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfX509Crl *crl2 = nullptr;
    ret = HcfX509CrlCreate(&inStreamInput, &crl2);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crl2, nullptr);
    CfFree(inStreamInput.data);
    CfObjDestroy(crl2);
    CfObjDestroy(x509Crl);
}

// Test crl getEncoded error
HWTEST_F(CryptoX509CrlTest, X509CrlTest033, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getEncoded(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getEncoded error
HWTEST_F(CryptoX509CrlTest, X509CrlTest034, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfEncodingBlob inStreamInput = { nullptr, 0, CF_FORMAT_PEM };
    CfResult ret = g_x509Crl->getEncoded(nullptr, &inStreamInput);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getEncoded error
HWTEST_F(CryptoX509CrlTest, X509CrlTest035, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getEncoded(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl verify true
HWTEST_F(CryptoX509CrlTest, X509CrlTest041, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509Certificate *x509CertObj = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamIssuerCert, &x509CertObj);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertObj, nullptr);

    HcfPubKey *keyOut = nullptr;
    ret = x509CertObj->base.getPublicKey((HcfCertificate *)x509CertObj, (void **)&keyOut);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(keyOut, nullptr);

    HcfBlob blob = { nullptr, 0 };
    HcfResult hcfRet = keyOut->base.getEncoded(&(keyOut->base), &blob);
    ASSERT_EQ(hcfRet, HCF_SUCCESS);

    HcfAsyKeyGenerator *generator = nullptr;
    hcfRet = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    ASSERT_EQ(hcfRet, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    hcfRet = generator->convertKey(generator, nullptr, &blob, nullptr, &dupKeyPair);
    ASSERT_EQ(hcfRet, HCF_SUCCESS);
    HcfPubKey *hcfPubkey = dupKeyPair->pubKey;

    ret = g_x509Crl->verify(g_x509Crl, hcfPubkey);
    EXPECT_EQ(ret, CF_SUCCESS);

    free(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(keyOut);
    HcfObjDestroy(generator);
    CfObjDestroy(x509CertObj);
}

// Test crl verify false
HWTEST_F(CryptoX509CrlTest, X509CrlTest042, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_3", &generator);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(keyPair, nullptr);

    CfResult ret1 = g_x509Crl->verify(g_x509Crl, keyPair->pubKey);
    EXPECT_NE(ret1, CF_SUCCESS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// Test crl verify false
HWTEST_F(CryptoX509CrlTest, X509CrlTest043, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult ret = HcfAsyKeyGeneratorCreate("RSA512|PRIMES_2", &generator);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(keyPair, nullptr);

    CfResult ret1 = g_x509Crl->verify(nullptr, keyPair->pubKey);
    EXPECT_NE(ret1, CF_SUCCESS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// Test crl verify false
HWTEST_F(CryptoX509CrlTest, X509CrlTest044, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->verify(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl verify false
HWTEST_F(CryptoX509CrlTest, X509CrlTest045, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    ret = x509Crl->verify(x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(x509Crl);
}

// Test crl getVersion true
HWTEST_F(CryptoX509CrlTest, X509CrlTest051, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    long version = g_x509Crl->getVersion(g_x509Crl);
    EXPECT_EQ(version, 2);
}

// Test crl getVersion false
HWTEST_F(CryptoX509CrlTest, X509CrlTest052, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    long version = g_x509Crl->getVersion(nullptr);
    EXPECT_EQ(version, -1);
}

// Test crl getIssuerName true
HWTEST_F(CryptoX509CrlTest, X509CrlTest061, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getIssuerName(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("/C=CN/O=test/CN=subca", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getIssuerName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest062, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getIssuerName(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getIssuerName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest063, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getIssuerName(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getIssuerName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest064, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getIssuerName(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getLastUpdate true
HWTEST_F(CryptoX509CrlTest, X509CrlTest071, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getLastUpdate(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("230912064750Z", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getLastUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest072, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getLastUpdate(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getLastUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest073, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getLastUpdate(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getLastUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest074, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getLastUpdate(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getNextUpdate true
HWTEST_F(CryptoX509CrlTest, X509CrlTest081, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getNextUpdate(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("231012064750Z", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getNextUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest082, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getNextUpdate(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getNextUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest083, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getNextUpdate(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getNextUpdate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest084, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getNextUpdate(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getRevokedCert true
HWTEST_F(CryptoX509CrlTest, X509CrlTest091, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);
    CfObjDestroy(crlEntry);
}

// Test crl getRevokedCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest092, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    long long testSn = 9999;
    CfBlob testSnBlob = { sizeof(testSn), (uint8_t *)&testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getRevokedCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest093, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getRevokedCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest094, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(nullptr, &testSnBlob, &crlEntry);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getRevokedCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest095, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(nullptr, &testSnBlob, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl entry getSerialNumber true
HWTEST_F(CryptoX509CrlTest, X509CrlTest101, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);
    CfBlob out = { 0, nullptr };
    ret = crlEntry->getSerialNumber(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(out.size, 2); /* out size: 2 bytes */
    EXPECT_EQ(out.data[0], g_testSn[0]);
    EXPECT_EQ(out.data[1], g_testSn[1]);
    CfFree(out.data);
    CfObjDestroy(crlEntry);
}

// Test crl entry getSerialNumber false
HWTEST_F(CryptoX509CrlTest, X509CrlTest102, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);
    ret = crlEntry->getSerialNumber(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getSerialNumber false
HWTEST_F(CryptoX509CrlTest, X509CrlTest103, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);
    ret = crlEntry->getSerialNumber(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getEncoded true
HWTEST_F(CryptoX509CrlTest, X509CrlTest111, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfEncodingBlob encodingBlob = { nullptr, 0, CF_FORMAT_PEM };
    ret = crlEntry->getEncoded(crlEntry, &encodingBlob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(encodingBlob.data, nullptr);
    CfObjDestroy(crlEntry);
    CfFree(encodingBlob.data);
}

// Test crl entry getEncoded false
HWTEST_F(CryptoX509CrlTest, X509CrlTest112, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfEncodingBlob encodingBlob = { nullptr, 0, CF_FORMAT_PEM };
    ret = crlEntry->getEncoded(nullptr, &encodingBlob);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(encodingBlob.data, nullptr);
    CfObjDestroy(crlEntry);
}

// Test crl entry getEncoded false
HWTEST_F(CryptoX509CrlTest, X509CrlTest113, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    ret = crlEntry->getEncoded(crlEntry, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getEncoded false
HWTEST_F(CryptoX509CrlTest, X509CrlTest114, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    ret = crlEntry->getEncoded(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getCertIssuer true
HWTEST_F(CryptoX509CrlTest, X509CrlTest121, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getCertIssuer(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("/C=CN/O=test/CN=subca", reinterpret_cast<char *>(out.data));
    CfObjDestroy(crlEntry);
    CfFree(out.data);
}

// Test crl entry getCertIssuer false
HWTEST_F(CryptoX509CrlTest, X509CrlTest122, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getCertIssuer(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
    CfObjDestroy(crlEntry);
}

// Test crl entry getCertIssuer false
HWTEST_F(CryptoX509CrlTest, X509CrlTest123, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    ret = crlEntry->getCertIssuer(crlEntry, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl entry getRevocationDate true
HWTEST_F(CryptoX509CrlTest, X509CrlTest131, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("230912064749Z", reinterpret_cast<char *>(out.data));
    CfObjDestroy(crlEntry);
    CfFree(out.data);
}

// Test crl entry getRevocationDate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest132, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
    CfObjDestroy(crlEntry);
}

// Test crl entry getRevocationDate false
HWTEST_F(CryptoX509CrlTest, X509CrlTest133, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    ret = crlEntry->getRevocationDate(crlEntry, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(crlEntry);
}

// Test crl getRevokedCertWithCert true
HWTEST_F(CryptoX509CrlTest, X509CrlTest141, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509Cert, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("230912064749Z", (char *)out.data);

    CfObjDestroy(x509Cert);
    CfObjDestroy(x509Crl);
    CfObjDestroy(crlEntry);
    CfFree(out.data);
}

// Test crl getRevokedCertWithCert true
HWTEST_F(CryptoX509CrlTest, X509CrlTest142, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509CertT142 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509CertT142);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509CertT142, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509CertT142, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getCertIssuer(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("/C=CN/O=test/CN=subca", (char *)out.data);

    CfObjDestroy(x509CertT142);
    CfObjDestroy(x509Crl);
    CfObjDestroy(crlEntry);
    CfFree(out.data);
}

// Test crl getRevokedCertWithCert true
HWTEST_F(CryptoX509CrlTest, X509CrlTest143, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509CertT143 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509CertT143);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509CertT143, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509CertT143, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfEncodingBlob encodingBlob = { nullptr, 0, CF_FORMAT_PEM };
    ret = crlEntry->getEncoded(crlEntry, &encodingBlob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(encodingBlob.data, nullptr);

    CfFree(encodingBlob.data);
    CfObjDestroy(x509CertT143);
    CfObjDestroy(x509Crl);
    CfObjDestroy(crlEntry);
}

// Test crl getRevokedCertWithCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest144, TestSize.Level0)
{
    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, nullptr, &crlEntry);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(crlEntry, nullptr);

    CfObjDestroy(x509Crl);
}

// Test crl getRevokedCertWithCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest145, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509Cert = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(nullptr, x509Cert, &crlEntry);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(crlEntry, nullptr);

    CfObjDestroy(x509Cert);
    CfObjDestroy(x509Crl);
}

// Test crl getRevokedCertWithCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest146, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509CertT146 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509CertT146);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509CertT146, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509CertT146, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);

    CfObjDestroy(x509CertT146);
    CfObjDestroy(x509Crl);
}

// Test crl getRevokedCertWithCert false
HWTEST_F(CryptoX509CrlTest, X509CrlTest147, TestSize.Level0)
{
    // Get cert
    HcfX509Certificate *x509CertT147 = nullptr;
    CfResult ret = HcfX509CertificateCreate(&g_inStreamCert, &x509CertT147);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509CertT147, nullptr);

    // Get crl
    HcfX509Crl *x509Crl = nullptr;
    ret = HcfX509CrlCreate(&g_inStreamCrl, &x509Crl);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    ret = x509Crl->getRevokedCertWithCert(x509Crl, x509CertT147, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);

    CfObjDestroy(x509CertT147);
    CfObjDestroy(x509Crl);
    CfObjDestroy(crlEntry);
}

// Test crl entry getRevokedCerts true
HWTEST_F(CryptoX509CrlTest, X509CrlTest151, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfArray entrysOut = { nullptr, CF_FORMAT_PEM, 0 };
    CfResult ret = g_x509Crl->getRevokedCerts(g_x509Crl, &entrysOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(entrysOut.data, nullptr);
    EXPECT_EQ(entrysOut.count, 2);

    HcfX509CrlEntry *crlEntry = reinterpret_cast<HcfX509CrlEntry *>(entrysOut.data[0].data);
    CfBlob out = { 0, nullptr };
    ret = crlEntry->getRevocationDate(crlEntry, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("230912064749Z", reinterpret_cast<char *>(out.data));

    CfFree(out.data);
    CfObjDestroy(entrysOut.data[0].data);
    CfObjDestroy(entrysOut.data[1].data);
    CfFree(entrysOut.data);
}

// Test crl entry getRevokedCerts false
HWTEST_F(CryptoX509CrlTest, X509CrlTest152, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getRevokedCerts(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl entry getRevokedCerts false
HWTEST_F(CryptoX509CrlTest, X509CrlTest153, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfArray entrysOut = { nullptr, CF_FORMAT_PEM, 0 };
    CfResult ret = g_x509Crl->getRevokedCerts(nullptr, &entrysOut);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(entrysOut.data, nullptr);
}

// Test crl entry getRevokedCerts false
HWTEST_F(CryptoX509CrlTest, X509CrlTest154, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getRevokedCerts(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getTbsInfo true
HWTEST_F(CryptoX509CrlTest, X509CrlTest161, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob tbsCertListOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getTbsInfo(g_x509Crl, &tbsCertListOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(tbsCertListOut.data, nullptr);
    CfFree(tbsCertListOut.data);
}

// Test crl getTbsInfo false
HWTEST_F(CryptoX509CrlTest, X509CrlTest162, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob tbsCertListOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getTbsInfo(nullptr, &tbsCertListOut);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(tbsCertListOut.data, nullptr);
}

// Test crl  getTbsInfo false
HWTEST_F(CryptoX509CrlTest, X509CrlTest163, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getTbsInfo(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getTbsInfo false
HWTEST_F(CryptoX509CrlTest, X509CrlTest164, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getTbsInfo(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignature true
HWTEST_F(CryptoX509CrlTest, X509CrlTest171, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob signature = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignature(g_x509Crl, &signature);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(signature.data, nullptr);
    CfFree(signature.data);
}

// Test crl getSignature false
HWTEST_F(CryptoX509CrlTest, X509CrlTest172, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob signature = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignature(nullptr, &signature);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(signature.data, nullptr);
}

// Test crl getSignature false
HWTEST_F(CryptoX509CrlTest, X509CrlTest173, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignature(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignature false
HWTEST_F(CryptoX509CrlTest, X509CrlTest174, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignature(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgName true
HWTEST_F(CryptoX509CrlTest, X509CrlTest181, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgName(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("SHA256withRSA", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getSignatureAlgName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest182, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgName(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getSignatureAlgName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest183, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgName(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgName false
HWTEST_F(CryptoX509CrlTest, X509CrlTest184, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgName(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgOid true
HWTEST_F(CryptoX509CrlTest, X509CrlTest191, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgOid(g_x509Crl, &out);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(out.data, nullptr);
    EXPECT_STREQ("1.2.840.113549.1.1.11", reinterpret_cast<char *>(out.data));
    CfFree(out.data);
}

// Test crl getSignatureAlgOid false
HWTEST_F(CryptoX509CrlTest, X509CrlTest192, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob out = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgOid(nullptr, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(out.data, nullptr);
}

// Test crl getSignatureAlgOid false
HWTEST_F(CryptoX509CrlTest, X509CrlTest193, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgOid(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgOid false
HWTEST_F(CryptoX509CrlTest, X509CrlTest194, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgOid(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgParams true
HWTEST_F(CryptoX509CrlTest, X509CrlTest201, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob sigAlgParamOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgParams(g_x509Crl, &sigAlgParamOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(sigAlgParamOut.data, nullptr);
    CfFree(sigAlgParamOut.data);
}

// Test crl getSignatureAlgParams false
HWTEST_F(CryptoX509CrlTest, X509CrlTest202, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob sigAlgParamOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getSignatureAlgParams(nullptr, &sigAlgParamOut);
    EXPECT_NE(ret, CF_SUCCESS);
    EXPECT_EQ(sigAlgParamOut.data, nullptr);
}

// Test crl getSignatureAlgParams false
HWTEST_F(CryptoX509CrlTest, X509CrlTest203, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgParams(g_x509Crl, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getSignatureAlgParams false
HWTEST_F(CryptoX509CrlTest, X509CrlTest204, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getSignatureAlgParams(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

// Test crl getExtensions return CF_INVALID_PARAMS
HWTEST_F(CryptoX509CrlTest, X509CrlTest205, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob blobOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getExtensions(nullptr, &blobOut);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    EXPECT_EQ(blobOut.data, nullptr);
}

// Test crl getExtensions return CF_INVALID_PARAMS
HWTEST_F(CryptoX509CrlTest, X509CrlTest206, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfResult ret = g_x509Crl->getExtensions(g_x509Crl, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

// Test crl getExtensions while there is no extension in the crl, return CF_SUCCESS
HWTEST_F(CryptoX509CrlTest, X509CrlTest207, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    int32_t nRet = HcfX509CrlCreate(&g_crlWithoutExtPemInStream, &x509Crl);
    ASSERT_EQ(nRet, 0);

    CfBlob blobOut = { 0, nullptr };
    CfResult cfRet = x509Crl->getExtensions(x509Crl, &blobOut);
    EXPECT_EQ(cfRet, CF_SUCCESS);
    EXPECT_EQ(blobOut.data, nullptr);
    CfFree(blobOut.data);
    CfObjDestroy(x509Crl);
}

// Test crl getExtensions while there are extensions in the crl, return CF_SUCCESS
HWTEST_F(CryptoX509CrlTest, X509CrlTest208, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob blobOut = { 0, nullptr };
    CfResult ret = g_x509Crl->getExtensions(g_x509Crl, &blobOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(blobOut.data, nullptr);
    CfFree(blobOut.data);
}

// Test crlEntry hasExtensions return false
HWTEST_F(CryptoX509CrlTest, X509CrlTest209, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    bool boolResult = true;
    CfResult result = crlEntry->hasExtensions(nullptr, &boolResult);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    CfObjDestroy(crlEntry);
}

// Test crlEntry hasExtensions  while there is no extension in the crlEntry,return CF_SUCCESS
HWTEST_F(CryptoX509CrlTest, X509CrlTest210, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    bool boolResult = false;
    CfResult result = crlEntry->hasExtensions(crlEntry, &boolResult);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_EQ(boolResult, false);

    CfObjDestroy(crlEntry);
}

// Test crlEntry hasExtensions  while there are extensions in the crlEntry,return CF_SUCCESS
HWTEST_F(CryptoX509CrlTest, X509CrlTest211, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    int32_t nRet = HcfX509CrlCreate(&g_crlWhichEntryWithExtInStream, &x509Crl);
    ASSERT_EQ(nRet, 0);

    HcfX509CrlEntry *crlEntry = nullptr;
    uint8_t testSN[] = { 0xAB, 0xCD };
    CfBlob testSnBlob = { 2, testSN };
    CfResult ret = x509Crl->getRevokedCert(x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    bool boolResult = false;
    CfResult result = crlEntry->hasExtensions(crlEntry, &boolResult);
    EXPECT_EQ(result, CF_SUCCESS);
    EXPECT_EQ(boolResult, true);

    CfObjDestroy(crlEntry);
    CfObjDestroy(x509Crl);
}

// Test crlEntry getExtensions,return CF_INVALID_PARAMS
HWTEST_F(CryptoX509CrlTest, X509CrlTest212, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob blob = { 0, nullptr };
    ret = crlEntry->getExtensions(nullptr, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    EXPECT_EQ(blob.data, nullptr);

    CfObjDestroy(crlEntry);
}

// Test crlEntry getExtensions,return CF_INVALID_PARAMS
HWTEST_F(CryptoX509CrlTest, X509CrlTest213, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    ret = crlEntry->getExtensions(crlEntry, nullptr);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(crlEntry);
}

// Test crlEntry getExtensions while there is no extension in crlEntry,return CF_SUCCESS
HWTEST_F(CryptoX509CrlTest, X509CrlTest214, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob blob = { 0, nullptr };
    ret = crlEntry->getExtensions(crlEntry, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(blob.size, 0);
    EXPECT_EQ(blob.data, nullptr);

    CfObjDestroy(crlEntry);
}

// Test crlEntry getExtensions while there is one extension in crlEntry,return CF_SUCCESS
HWTEST_F(CryptoX509CrlTest, X509CrlTest215, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    int32_t nRet = HcfX509CrlCreate(&g_crlWhichEntryWithExtInStream, &x509Crl);
    ASSERT_EQ(nRet, 0);

    HcfX509CrlEntry *crlEntry = nullptr;
    uint8_t testSN[] = { 0xAB, 0xCD };
    CfBlob testSnBlob = { 2, testSN };
    CfResult ret = x509Crl->getRevokedCert(x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob blob = { 0, nullptr };
    ret = crlEntry->getExtensions(crlEntry, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(blob.size, 0);
    EXPECT_NE(blob.data, nullptr);

    CfObjDestroy(crlEntry);
    CfFree(blob.data);
    CfObjDestroy(x509Crl);
}

// Test crlEntry getExtensions while there are more than one extensions in crlEntry,return CF_SUCCESS
HWTEST_F(CryptoX509CrlTest, X509CrlTest216, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob blob = { 0, nullptr };
    ret = crlEntry->getExtensions(crlEntry, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfObjDestroy(crlEntry);
    CfFree(blob.data);
}

// Test crlEntry getRevokedCert while there is a big num serialNumber,return CF_SUCCESS
HWTEST_F(CryptoX509CrlTest, X509CrlTest217, TestSize.Level0)
{
    HcfX509Crl *x509Crl = nullptr;
    int32_t nRet = HcfX509CrlCreate(&g_crlWithBignumSerialInStream, &x509Crl);
    ASSERT_EQ(nRet, 0);
    ASSERT_NE(x509Crl, nullptr);

    HcfX509CrlEntry *crlEntry = nullptr;
    // Serial Number: FF01FF01FF01FF01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF01
    uint8_t testSn[] = { 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
    CfBlob testSnBlob = { sizeof(testSn) / sizeof(testSn[0]), testSn };
    CfResult cfRet = x509Crl->getRevokedCert(x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(cfRet, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfObjDestroy(crlEntry);
    CfObjDestroy(x509Crl);
}

// Test crlEntry hasExtensions return false
HWTEST_F(CryptoX509CrlTest, X509CrlTest218, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    bool boolResult = true;
    CfObjectBase obj = { GetInvalidCrlClass, nullptr };
    CfResult result = crlEntry->hasExtensions((HcfX509CrlEntry *)&obj, &boolResult);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    CfObjDestroy(crlEntry);
}

// Test crlEntry getExtensions return false
HWTEST_F(CryptoX509CrlTest, X509CrlTest219, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob testSnBlob = { 2, g_testSn };
    CfResult ret = g_x509Crl->getRevokedCert(g_x509Crl, &testSnBlob, &crlEntry);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(crlEntry, nullptr);

    CfBlob blob = { 0, nullptr };
    CfObjectBase obj = { GetInvalidCrlClass, nullptr };
    CfResult result = crlEntry->getExtensions((HcfX509CrlEntry *)&obj, &blob);
    EXPECT_EQ(result, CF_INVALID_PARAMS);

    CfObjDestroy(crlEntry);
}

HWTEST_F(CryptoX509CrlTest, NullSpi, TestSize.Level0)
{
    HcfX509CrlSpi *spiObj = nullptr;
    CfBlob serialBlob = { 0, nullptr };
    SetMockFlag(true);
    (void)HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);
    SetMockFlag(false);
    (void)HcfCX509CrlSpiCreate(nullptr, &spiObj);
    CfEncodingBlob blob = { nullptr, 0, CF_FORMAT_DER };
    (void)HcfCX509CrlSpiCreate(&blob, &spiObj);
    (void)HcfCX509CrlSpiCreate(&g_crlDerInStream, nullptr);

    CfResult ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    (void)spiObj->base.destroy(nullptr);
    const char *tmp = spiObj->engineGetType(nullptr);
    EXPECT_EQ(tmp, nullptr);
    bool flag = spiObj->engineIsRevoked(nullptr, nullptr);
    EXPECT_EQ(flag, false);
    ret = spiObj->engineGetEncoded(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineVerify(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    long ver = spiObj->engineGetVersion(nullptr);
    EXPECT_EQ(ver, -1);
    ret = spiObj->engineGetIssuerName(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetLastUpdate(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetNextUpdate(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetRevokedCert(nullptr, &serialBlob, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetRevokedCertWithCert(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetRevokedCerts(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetTbsInfo(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignature(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgName(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgOid(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgParams(nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineMatch(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);

    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CrlTest, NullSpi2, TestSize.Level0)
{
    HcfX509CrlSpi *spiObj = nullptr;
    CfBlob out = { 0, nullptr };

    CfResult ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(spiObj, nullptr);

    ret = spiObj->engineGetExtensions(nullptr, &out);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CrlTest, InvalidCrlSpiClass, TestSize.Level0)
{
    HcfX509CrlSpi invalidSpi = { { 0 } };
    CfBlob serialBlob = { 0, nullptr };
    invalidSpi.base.getClass = GetInvalidCrlClass;
    CfBlob invalidOut = { 0, nullptr };
    CfEncodingBlob encoding = { nullptr, 0, CF_FORMAT_PEM };
    HcfX509CrlEntry *entry = nullptr;
    HcfX509CrlSpi *spiObj = nullptr;
    CfResult ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);
    (void)spiObj->base.destroy(&(invalidSpi.base));
    const char *tmp = spiObj->engineGetType(&invalidSpi);
    EXPECT_EQ(tmp, nullptr);
    HcfCertificate cert;
    bool flag = spiObj->engineIsRevoked(&invalidSpi, &cert);
    EXPECT_EQ(flag, false);
    ret = spiObj->engineGetEncoded(&invalidSpi, &encoding);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfPubKey pubKey;
    ret = spiObj->engineVerify(&invalidSpi, &pubKey);
    EXPECT_NE(ret, CF_SUCCESS);
    long ver = spiObj->engineGetVersion(&invalidSpi);
    EXPECT_EQ(ver, -1);
    ret = spiObj->engineGetIssuerName(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetLastUpdate(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetNextUpdate(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetRevokedCert(&invalidSpi, &serialBlob, &entry);
    EXPECT_NE(ret, CF_SUCCESS);

    HcfX509Certificate x509Cert;
    ret = spiObj->engineGetRevokedCertWithCert(&invalidSpi, &x509Cert, &entry);
    EXPECT_NE(ret, CF_SUCCESS);
    CfArray invalidArr = { nullptr, CF_FORMAT_PEM, 0 };
    ret = spiObj->engineGetRevokedCerts(&invalidSpi, &invalidArr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetTbsInfo(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignature(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgName(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgOid(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = spiObj->engineGetSignatureAlgParams(&invalidSpi, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CrlTest, InvalidCrlSpiClass2, TestSize.Level0)
{
    HcfX509CrlSpi invalidSpi = { { 0 } };
    invalidSpi.base.getClass = GetInvalidCrlClass;
    HcfX509CrlEntry *entry = nullptr;
    HcfX509CrlSpi *spiObj = nullptr;
    CfResult ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);

    CfBlob testSnBlob = { 2, g_testSn };
    ret = spiObj->engineGetRevokedCert(&invalidSpi, &testSnBlob, &entry);
    EXPECT_NE(ret, CF_SUCCESS);

    HcfX509CrlMatchParams matchParams;
    bool bOut = true;
    ret = spiObj->engineMatch(&invalidSpi, &matchParams, &bOut);
    EXPECT_NE(ret, CF_SUCCESS);
    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CrlTest, InvalidCrlClass, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    CfBlob serialBlob = { 0, nullptr };
    HcfX509Crl invalidCrl;
    invalidCrl.base.base.getClass = GetInvalidCrlClass;
    CfBlob invalidOut = { 0, nullptr };
    CfEncodingBlob encoding = { nullptr, 0, CF_FORMAT_PEM };
    HcfX509CrlEntry *entry = nullptr;

    g_x509Crl->base.base.destroy(nullptr);
    g_x509Crl->base.base.destroy(&(invalidCrl.base.base));
    const char *tmp = g_x509Crl->base.getType(&(invalidCrl.base));
    EXPECT_EQ(tmp, nullptr);
    HcfCertificate cert;
    bool flag = g_x509Crl->base.isRevoked(&(invalidCrl.base), &cert);
    EXPECT_EQ(flag, false);
    CfResult ret = g_x509Crl->getEncoded(&invalidCrl, &encoding);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfPubKey pubKey;
    ret = g_x509Crl->verify(&invalidCrl, &pubKey);
    EXPECT_NE(ret, CF_SUCCESS);
    long ver = g_x509Crl->getVersion(&invalidCrl);
    EXPECT_EQ(ver, -1);
    ret = g_x509Crl->getIssuerName(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getLastUpdate(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getNextUpdate(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getRevokedCert(&invalidCrl, &serialBlob, &entry);
    EXPECT_NE(ret, CF_SUCCESS);
    HcfX509Certificate x509Cert;
    ret = g_x509Crl->getRevokedCertWithCert(&invalidCrl, &x509Cert, &entry);
    EXPECT_NE(ret, CF_SUCCESS);
    CfArray invalidArr = { nullptr, CF_FORMAT_PEM, 0 };
    ret = g_x509Crl->getRevokedCerts(&invalidCrl, &invalidArr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getTbsInfo(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignature(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgName(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgOid(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgParams(&invalidCrl, &invalidOut);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CrlTest, InvalidCrlClass2, TestSize.Level0)
{
    HcfX509CrlMatchParams matchParams;
    HcfX509Crl invalidCrl;
    invalidCrl.base.base.getClass = GetInvalidCrlClass;
    bool bOut = true;
    CfResult ret = g_x509Crl->match(&invalidCrl, &matchParams, &bOut);
    EXPECT_NE(ret, CF_SUCCESS);
}

HWTEST_F(CryptoX509CrlTest, InvalidMalloc, TestSize.Level0)
{
    ASSERT_NE(g_x509Crl, nullptr);
    SetMockFlag(true);
    CfBlob out = { 0, nullptr };
    CfEncodingBlob encoding = { nullptr, 0, CF_FORMAT_PEM };
    HcfX509CrlEntry *entry = nullptr;
    CfResult ret = g_x509Crl->getEncoded(g_x509Crl, &encoding);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getIssuerName(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getLastUpdate(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getNextUpdate(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getRevokedCert(g_x509Crl, &out, &entry);
    EXPECT_NE(ret, CF_SUCCESS);
    CfArray arr = { nullptr, CF_FORMAT_PEM, 0 };
    ret = g_x509Crl->getRevokedCerts(g_x509Crl, &arr);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getTbsInfo(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignature(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgName(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgOid(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    ret = g_x509Crl->getSignatureAlgParams(g_x509Crl, &out);
    EXPECT_NE(ret, CF_SUCCESS);
    SetMockFlag(false);
}

HWTEST_F(CryptoX509CrlTest, HcfCX509CRLEntryCreateInvalid, TestSize.Level0)
{
    SetMockFlag(true);
    X509_REVOKED *rev = X509_REVOKED_new();
    HcfX509CrlEntry *crlEntryOut = nullptr;
    CfBlob certIssuer;
    CfResult ret = HcfCX509CRLEntryCreate(rev, &crlEntryOut, &certIssuer);
    EXPECT_NE(ret, CF_SUCCESS);
    SetMockFlag(false);

    ret = HcfCX509CRLEntryCreate(nullptr, &crlEntryOut, &certIssuer);
    EXPECT_NE(ret, CF_SUCCESS);

    ret = HcfCX509CRLEntryCreate(rev, nullptr, &certIssuer);
    EXPECT_NE(ret, CF_SUCCESS);

    ret = HcfCX509CRLEntryCreate(rev, &crlEntryOut, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);

    ret = HcfCX509CRLEntryCreate(rev, &crlEntryOut, &certIssuer);
    EXPECT_NE(ret, CF_SUCCESS);

    X509_REVOKED_free(rev);
}

HWTEST_F(CryptoX509CrlTest, CompareUpdateDateTimeTest001, TestSize.Level0)
{
    CF_LOG_I("CompareUpdateDateTimeTest001");
    HcfX509CrlSpi *spiObj = nullptr;
    CfResult ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);

    HcfX509CrlMatchParams matchParams;
    CfBlob blob;
    blob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testUpdateDateTime));
    blob.size = strlen(g_testUpdateDateTime) + 1;
    matchParams.updateDateTime = &blob;

    bool bOut = true;
    ret = spiObj->engineMatch(spiObj, &matchParams, &bOut);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CrlTest, CompareMaxCRLTest001, TestSize.Level0)
{
    CF_LOG_I("CompareMaxCRLTest001");
    HcfX509CrlSpi *spiObj = nullptr;
    CfResult ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);

    HcfX509CrlMatchParams matchParams;
    CfBlob blob;
    blob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testUpdateDateTime));
    blob.size = strlen(g_testUpdateDateTime) + 1;
    matchParams.maxCRL = &blob;

    bool bOut = true;
    ret = spiObj->engineMatch(spiObj, &matchParams, &bOut);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CrlTest, CompareMinCRLTest001, TestSize.Level0)
{
    CF_LOG_I("CompareMinCRLTest001");
    HcfX509CrlSpi *spiObj = nullptr;
    CfResult ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);

    HcfX509CrlMatchParams matchParams;
    CfBlob blob;
    blob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testUpdateDateTime));
    blob.size = strlen(g_testUpdateDateTime) + 1;
    matchParams.minCRL = &blob;

    bool bOut = true;
    ret = spiObj->engineMatch(spiObj, &matchParams, &bOut);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CrlTest, GetX509FromCertificateBranchTest, TestSize.Level0)
{
    CF_LOG_I("GetX509FromCertificateBranchTest");
    HcfX509CrlSpi invalidSpi = { { 0 } };
    invalidSpi.base.getClass = GetValidCrlClass;
    HcfX509CrlEntry *entry = nullptr;
    HcfX509CrlSpi *spiObj = nullptr;

    // test ParseX509CRL invalid encodingFormat
    CfResult ret = HcfCX509CrlSpiCreate(&g_invalidCrlDerInStream, &spiObj);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = HcfCX509CrlSpiCreate(&g_crlDerInStream, &spiObj);
    EXPECT_EQ(ret, CF_SUCCESS);

    HcfCertificate cert;
    cert.base.getClass = GetInvalidCertClass;
    bool flag = spiObj->engineIsRevoked(&invalidSpi, &cert);
    EXPECT_EQ(flag, false);

    HcfX509Certificate x509Cert;
    x509Cert.base.base.getClass = GetInvalidCertClass;
    ret = spiObj->engineGetRevokedCertWithCert(&invalidSpi, &x509Cert, &entry);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    x509Cert.base.base.getClass = GetValidX509CertificateClass;
    HcfX509CertificateImpl *impl = (HcfX509CertificateImpl *)(&x509Cert);
    HcfX509CertificateSpi spi;
    impl->spiObj = &spi;
    ((CfObjectBase *)(impl->spiObj))->getClass = GetInvalidCertClass;
    ret = spiObj->engineGetRevokedCertWithCert(&invalidSpi, &x509Cert, &entry);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    CfObjDestroy(spiObj);
}
} // namespace
