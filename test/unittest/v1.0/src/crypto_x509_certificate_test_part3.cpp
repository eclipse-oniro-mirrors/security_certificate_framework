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

#include "certificate_openssl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "config.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "securec.h"
#include "x509_certificate.h"
#include "x509_certificate_openssl.h"

#define OID_STR_MAX_LEN 128
#define CONSTRUCT_EXTENDED_KEY_USAGE_DATA_SIZE 1
#define ARRAY_INDEX2 2

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
long __real_ASN1_INTEGER_get(const ASN1_INTEGER *a);
void *__real_X509V3_EXT_d2i(X509_EXTENSION *ext);
X509_EXTENSION *__real_X509_get_ext(const X509 *x, X509_EXTENSION *loc);
void *__real_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
CfResult __real_DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob);
int __real_X509_print(BIO *bp, X509 *x);
BIO *__real_BIO_new(const BIO_METHOD *type);

#ifdef __cplusplus
}
#endif

namespace {
class CryptoX509CertificateTestPart3 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static HcfX509Certificate *g_x509CertExtAttrObj = nullptr;
static HcfX509Certificate *g_testCertWithPrivateKeyValidObj = nullptr;

void CryptoX509CertificateTestPart3::SetUpTestCase()
{
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testExtAttrCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testExtAttrCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &g_x509CertExtAttrObj);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertWithPrivateKeyValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testCertWithPrivateKeyValid) + 1;
    (void)HcfX509CertificateCreate(&inStream, &g_testCertWithPrivateKeyValidObj);
}

void CryptoX509CertificateTestPart3::TearDownTestCase()
{
    CfObjDestroy(g_x509CertExtAttrObj);
    CfObjDestroy(g_testCertWithPrivateKeyValidObj);
}

void CryptoX509CertificateTestPart3::SetUp() {}

void CryptoX509CertificateTestPart3::TearDown() {}

static CfArray *constructExtendedKeyUsageData()
{
    CfArray *newBlobArr = static_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
    if (newBlobArr == nullptr) {
        CF_LOG_E("Failed to allocate newBlobArr memory!");
        return nullptr;
    }

    newBlobArr->count = CONSTRUCT_EXTENDED_KEY_USAGE_DATA_SIZE;
    newBlobArr->format = CF_FORMAT_DER;
    newBlobArr->data = static_cast<CfBlob *>(CfMalloc(newBlobArr->count * sizeof(CfBlob), 0));
    if (newBlobArr->data == nullptr) {
        CF_LOG_E("Failed to allocate data memory!");
        CfFree(newBlobArr);
        return nullptr;
    }

    newBlobArr->data[0].data = const_cast<uint8_t *>(g_testExtendedKeyUsage);
    newBlobArr->data[0].size = sizeof(g_testExtendedKeyUsage);

    return newBlobArr;
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareSubjectAlternativeNamesTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };
    certMatchParameters.subjectAlternativeNames = ConstructSubAltNameArrayData();
    EXPECT_NE(certMatchParameters.subjectAlternativeNames, nullptr);

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    certMatchParameters.minPathLenConstraint = -1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    CfFree(certMatchParameters.subjectAlternativeNames->data);
    CfFree(certMatchParameters.subjectAlternativeNames);
    certMatchParameters.subjectAlternativeNames = nullptr;
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareSubjectAlternativeNamesTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams matchParams;
    matchParams.subjectAlternativeNames = ConstructSubAltNameArrayData();
    EXPECT_NE(matchParams.subjectAlternativeNames, nullptr);

    // test DeepCopySubAltName failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_GENERAL_NAME(_, _)).Times(AnyNumber()).WillOnce(Return(-1));
    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    // test CompareSubAltNameX509Openssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    SetMockFlag(true);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    CfFree(matchParams.subjectAlternativeNames->data);
    CfFree(matchParams.subjectAlternativeNames);
    matchParams.subjectAlternativeNames = nullptr;
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareMatchAllSubjectAltNamesTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;
    CfResult ret = CF_SUCCESS;
    HcfX509CertMatchParams certMatchParameters = { 0 };
    certMatchParameters.matchAllSubjectAltNames = true;
    certMatchParameters.subjectAlternativeNames = ConstructSubAltNameArrayData();
    EXPECT_NE(certMatchParameters.subjectAlternativeNames, nullptr);

    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    certMatchParameters.minPathLenConstraint = -1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    certMatchParameters.subjectAlternativeNames->count = 2;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // add failed case ret != CF_SUCCESS
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_num(_))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfFree(certMatchParameters.subjectAlternativeNames->data);
    CfFree(certMatchParameters.subjectAlternativeNames);
    certMatchParameters.subjectAlternativeNames = nullptr;
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareAuthorityKeyIdentifierTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testIssuer);
    blob.size = sizeof(g_testIssuer);

    certMatchParameters.authorityKeyIdentifier = &blob;

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    certMatchParameters.minPathLenConstraint = -1;
    blob.data = const_cast<uint8_t *>(g_testAuthorityKeyIdentifier);
    blob.size = sizeof(g_testAuthorityKeyIdentifier);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test GetAuKeyIdDNX509Openssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_AUTHORITY_KEYID(_, _)).Times(AnyNumber()).WillOnce(Return(-1));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), DeepCopyDataToBlob(_, _, _))
        .WillOnce(Return(CF_INVALID_PARAMS))
        .WillRepeatedly(Invoke(__real_DeepCopyDataToBlob));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareMinPathLenConstraintTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };
    certMatchParameters.minPathLenConstraint = 100000;

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // test DetailForMinPathLenConstraint failed case
    certMatchParameters.minPathLenConstraint = -2;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    BASIC_CONSTRAINTS *constraints = BASIC_CONSTRAINTS_new();
    EXPECT_NE(constraints, nullptr);
    constraints->ca = 1;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509V3_EXT_d2i(_)).Times(AnyNumber()).WillOnce(Return(constraints));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareMinPathLenConstraintTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };
    certMatchParameters.minPathLenConstraint = 100000;

    CfResult ret;

    BASIC_CONSTRAINTS *constraints = BASIC_CONSTRAINTS_new();
    EXPECT_NE(constraints, nullptr);
    ASN1_INTEGER *pathlen = ASN1_INTEGER_new();
    EXPECT_NE(pathlen, nullptr);
    pathlen->type = V_ASN1_NEG_INTEGER;
    constraints->ca = 0;
    constraints->pathlen = pathlen;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509V3_EXT_d2i(_)).Times(AnyNumber()).WillOnce(Return(constraints));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_INTEGER_get(_))
        .WillOnce(Return(10))
        .WillRepeatedly(Invoke(__real_ASN1_INTEGER_get));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509V3_EXT_d2i(_))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_X509V3_EXT_d2i));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext(_, _)).Times(AnyNumber()).WillOnce(Return(NULL));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    certMatchParameters.minPathLenConstraint = 2;
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext(_, _))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_X509_get_ext));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareExtendedKeyUsageTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;
    CfResult ret;
    HcfX509CertMatchParams certMatchParameters = { 0 };

    certMatchParameters.extendedKeyUsage = constructExtendedKeyUsageData();
    EXPECT_NE(certMatchParameters.extendedKeyUsage, nullptr);

    certMatchParameters.minPathLenConstraint = -1;

    // todo add failed case bResult = true
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // todo add failed case ret != CF_SUCCESS
    SetMockFlag(true);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    // test IsSubset failed case
    certMatchParameters.extendedKeyUsage->data[0].size -= 1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfFree(certMatchParameters.extendedKeyUsage->data);
    CfFree(certMatchParameters.extendedKeyUsage);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraints);
    blob.size = sizeof(g_testNameConstraints);
    certMatchParameters.nameConstraints = &blob;

    CfResult ret =
        g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    certMatchParameters.minPathLenConstraint = -1;
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test CompareNameConstraintsX509Openssl failed case
    // GEN_OTHERNAME
    GENERAL_SUBTREE *tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_OTHERNAME;
    tree->base->d.otherName = OTHERNAME_new();

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(tree))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    // GEN_X400
    tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_X400;
    tree->base->d.x400Address = ASN1_STRING_new();

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(tree))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraints);
    blob.size = sizeof(g_testNameConstraints);
    certMatchParameters.nameConstraints = &blob;

    // GEN_IPADD
    GENERAL_SUBTREE *tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_IPADD;
    tree->base->d.ip = ASN1_OCTET_STRING_new();
    blob.data = const_cast<uint8_t *>(g_testNameConstraintsIPADDR);
    blob.size = sizeof(g_testNameConstraintsIPADDR);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _)).Times(AnyNumber()).WillOnce(Return(tree));
    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest003, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraintsEDIParty);
    blob.size = sizeof(g_testNameConstraintsEDIParty);
    certMatchParameters.nameConstraints = &blob;

    // GEN_EDIPARTY g_testNameConstraintsEDIPartyInvalid
    GENERAL_SUBTREE *tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_EDIPARTY;
    tree->base->d.ediPartyName = EDIPARTYNAME_new();

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _)).Times(AnyNumber()).WillOnce(Return(tree));
    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_EDIPARTY;
    tree->base->d.ediPartyName = EDIPARTYNAME_new();
    blob.data = const_cast<uint8_t *>(g_testNameConstraintsEDIPartyInvalid);
    blob.size = sizeof(g_testNameConstraintsEDIPartyInvalid);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _)).Times(AnyNumber()).WillOnce(Return(tree));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest004, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraints);
    blob.size = sizeof(g_testNameConstraints);
    certMatchParameters.nameConstraints = &blob;

    CfResult ret;

    // GEN_DIRNAME
    GENERAL_SUBTREE *tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_DIRNAME;
    tree->base->d.directoryName = X509_NAME_new();

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _)).Times(AnyNumber()).WillOnce(Return(tree));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    // GEN_RID
    tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_RID;
    tree->base->d.registeredID = ASN1_OBJECT_new();

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(tree))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest005, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraints);
    blob.size = sizeof(g_testNameConstraints);
    certMatchParameters.nameConstraints = &blob;

    CfResult ret;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _)).Times(AnyNumber()).WillOnce(Return(NULL));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    NAME_CONSTRAINTS *nc = NAME_CONSTRAINTS_new();
    EXPECT_NE(nc, nullptr);
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _)).Times(AnyNumber()).WillOnce(Return(nc));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    nc = NAME_CONSTRAINTS_new();
    EXPECT_NE(nc, nullptr);
    nc->permittedSubtrees = sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(nc, nullptr);
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .WillOnce(Return(nc))
        .WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareCertPolicyTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams matchParams;
    matchParams.certPolicy = ConstructCertPolicyData();
    EXPECT_NE(matchParams.certPolicy, nullptr);
    SetMockFlag(true);
    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    SetMockFlag(false);

    CfFree(matchParams.certPolicy->data);
    CfFree(matchParams.certPolicy);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareCertPolicyTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    certMatchParameters.certPolicy = ConstructCertPolicyData();

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // todo add failed case bResult = true
    certMatchParameters.minPathLenConstraint = -1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test IsSubset failed case
    certMatchParameters.certPolicy->data[0].size -= 1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfFree(certMatchParameters.certPolicy->data);
    CfFree(certMatchParameters.certPolicy);
}

HWTEST_F(CryptoX509CertificateTestPart3, ComparePrivateKeyValidTest001, TestSize.Level0)
{
    ASSERT_NE(g_testCertWithPrivateKeyValidObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPrivateKeyValid));
    blob.size = strlen(g_testPrivateKeyValid) + 1;
    certMatchParameters.privateKeyValid = &blob;

    CfResult ret =
        g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // todo add failed case bResult = true
    certMatchParameters.minPathLenConstraint = -1;
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test asn1TimeToStr failed case
    X509OpensslMock::SetMockFlag(true);
    PKEY_USAGE_PERIOD *pKeyValid = reinterpret_cast<PKEY_USAGE_PERIOD *>(CfMalloc(sizeof(PKEY_USAGE_PERIOD), 0));
    EXPECT_NE(pKeyValid, nullptr);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(pKeyValid));
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    pKeyValid = reinterpret_cast<PKEY_USAGE_PERIOD *>(CfMalloc(sizeof(PKEY_USAGE_PERIOD), 0));
    ASSERT_NE(pKeyValid, nullptr);
    pKeyValid->notBefore = reinterpret_cast<ASN1_GENERALIZEDTIME *>(CfMalloc(sizeof(ASN1_GENERALIZEDTIME), 0));
    ASSERT_NE(pKeyValid->notBefore, nullptr);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(pKeyValid));
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, ComparePrivateKeyValidTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPrivateKeyInvalid));
    blob.size = strlen(g_testPrivateKeyInvalid) + 1;
    certMatchParameters.privateKeyValid = &blob;

    CfResult ret;

    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    X509OpensslMock::SetMockFlag(true);
    PKEY_USAGE_PERIOD *pKeyValid = reinterpret_cast<PKEY_USAGE_PERIOD *>(CfMalloc(sizeof(PKEY_USAGE_PERIOD), 0));
    ASSERT_NE(pKeyValid, nullptr);
    pKeyValid->notBefore = reinterpret_cast<ASN1_GENERALIZEDTIME *>(CfMalloc(sizeof(ASN1_GENERALIZEDTIME), 0));
    ASSERT_NE(pKeyValid->notBefore, nullptr);
    pKeyValid->notBefore->data = (unsigned char *)strdup(g_testPrivateKeyValid);
    ASSERT_NE(pKeyValid->notBefore->data, nullptr);

    pKeyValid->notBefore->length = strlen(g_testPrivateKeyValid);
    pKeyValid->notAfter = nullptr;
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(pKeyValid));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    // test ComparePrivateKeyValidX509Openssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _)).Times(AnyNumber()).WillOnce(Return(NULL));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareSubjectKeyIdentifierTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };
    CfBlob blob;

    blob.data = const_cast<uint8_t *>(g_testIssuer);
    blob.size = sizeof(g_testIssuer);
    certMatchParameters.subjectKeyIdentifier = &blob;

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // todo add failed case bResult = true
    certMatchParameters.minPathLenConstraint = -1;
    blob.data = const_cast<uint8_t *>(g_testSubjectKeyIdentifier);
    blob.size = sizeof(g_testSubjectKeyIdentifier);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test GetSubKeyIdDNX509Openssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_ASN1_OCTET_STRING(_, _)).Times(AnyNumber()).WillOnce(Return(-1));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _)).Times(AnyNumber()).WillOnce(Return(NULL));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), DeepCopyDataToBlob(_, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(CF_INVALID_PARAMS));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, ToStringTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertificateTestPart3 - ToStringTest001");
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509Certificate invalidCert;
    invalidCert.base.base.getClass = GetInvalidCertClass;

    ret = g_x509CertExtAttrObj->toString(&invalidCert, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->toString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->toString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(NULL))
        .WillRepeatedly(Invoke(__real_BIO_new));
    ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_print(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_X509_print));
    ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_ctrl(_, _, _, _)).Times(AnyNumber()).WillOnce(Return(0));
    ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, HashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertificateTestPart3 - HashCodeTest001");
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    SetMockFlag(true);
    ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509(_, _)).Times(AnyNumber()).WillOnce(Return(-1));
    ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509(_, _)).Times(AnyNumber()).WillOnce(Return(0));
    ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    HcfX509Certificate invalidCert;
    invalidCert.base.base.getClass = GetInvalidCertClass;

    ret = g_x509CertExtAttrObj->hashCode(&invalidCert, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->hashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->hashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertificateTestPart3, GetExtensionsObjectTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertificateTestPart3 - GetExtensionsObjectTest001");
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509CertExtAttrObj->getExtensionsObject(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509_EXTENSIONS(_, _)).Times(AnyNumber()).WillOnce(Return(-1));
    ret = g_x509CertExtAttrObj->getExtensionsObject(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    HcfX509Certificate invalidCert;
    invalidCert.base.base.getClass = GetInvalidCertClass;

    ret = g_x509CertExtAttrObj->getExtensionsObject(&invalidCert, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->getExtensionsObject(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->getExtensionsObject(g_x509CertExtAttrObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->getExtensionsObject(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

} // namespace
