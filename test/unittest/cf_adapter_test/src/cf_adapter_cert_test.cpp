/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cf_adapter_cert_openssl.h"
#include "cf_test_common.h"
#include "cf_magic.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "cf_test_data.h"
#include "cf_test_common.h"

using namespace testing::ext;
using namespace CertframeworkTest;
using namespace CertframeworkTestData;

namespace {
CfEncodingBlob g_cert[] = {
    { const_cast<uint8_t *>(g_certData01), sizeof(g_certData01), CF_FORMAT_DER },
    { reinterpret_cast<uint8_t *>(g_certData02), strlen(g_certData02) + 1, CF_FORMAT_PEM }
};

CfBlob g_certExtension[] = {
    { sizeof(g_extensionData01), const_cast<uint8_t *>(g_extensionData01) },
    { sizeof(g_certData02Extension), const_cast<uint8_t *>(g_certData02Extension) },
};

CfBlob g_certTBS[] = {
    { sizeof(g_certData01TBS), const_cast<uint8_t *>(g_certData01TBS) },
    { sizeof(g_certData02TBS), const_cast<uint8_t *>(g_certData02TBS) },
};

class CfAdapterCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CfAdapterCertTest::SetUpTestCase(void)
{
}

void CfAdapterCertTest::TearDownTestCase(void)
{
}

void CfAdapterCertTest::SetUp()
{
}

void CfAdapterCertTest::TearDown()
{
}

/**
 * @tc.name: OpensslCreateCertTest001
 * @tc.desc: Test CertFramework adapter create cert object interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest001, TestSize.Level0)
{
    CfBase *derObj = nullptr; /* der format cert object */
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &derObj);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfOpensslDestoryCert(&derObj);
}

/**
 * @tc.name: OpensslCreateCertTest002
 * @tc.desc: Test CertFramework adapter create cert object interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest002, TestSize.Level0)
{
    CfBase *pemObj = nullptr; /* pem format cert object */
    int32_t ret = CfOpensslCreateCert(&g_cert[1], &pemObj);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfOpensslDestoryCert(&pemObj);
}

/**
 * @tc.name: OpensslCreateCertTest003
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest003, TestSize.Level0)
{
    CfBase *obj001 = nullptr;
    CfEncodingBlob *invalCert001 = nullptr; /* cert blob is nullptr */
    int32_t ret = CfOpensslCreateCert(invalCert001, &obj001);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter create cert object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateCertTest004
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest004, TestSize.Level0)
{
    CfBase *obj002 = nullptr;
    CfEncodingBlob invalCert002 = { nullptr, 20, CF_FORMAT_DER }; /* cert data is nullptr */
    int32_t ret = CfOpensslCreateCert(&invalCert002, &obj002);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter create cert object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateCertTest005
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest005, TestSize.Level0)
{
    CfBase *obj003 = nullptr;
    CfEncodingBlob invalCert003 = { const_cast<uint8_t *>(g_certData01), 0, CF_FORMAT_DER }; /* cert size is 0 */
    int32_t ret = CfOpensslCreateCert(&invalCert003, &obj003);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter create cert object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateCertTest006
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest006, TestSize.Level0)
{
    CfBase *obj004 = nullptr;
    /* cert format is invalid */
    CfEncodingBlob invalCert004 = {
        const_cast<uint8_t *>(g_certData03),
        sizeof(g_certData03),
        static_cast<enum CfEncodingFormat>(CF_FORMAT_PEM + 1)
    };
    int32_t ret = CfOpensslCreateCert(&invalCert004, &obj004);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter create cert object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateCertTest007
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest007, TestSize.Level0)
{
    CfBase *obj005 = nullptr;
    /* cert size beyond max */
    CfEncodingBlob invalCert005 = { const_cast<uint8_t *>(g_certData03), MAX_LEN_CERTIFICATE + 1, CF_FORMAT_DER };
    int32_t ret = CfOpensslCreateCert(&invalCert005, &obj005);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter create cert object test failed, recode:" << ret;

    obj005 = nullptr;
    invalCert005.len = MAX_LEN_CERTIFICATE; /* cert size equal max */
    ret = CfOpensslCreateCert(&invalCert005, &obj005);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) << "Abnormal adapter create cert object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateCertTest008
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest008, TestSize.Level0)
{
    int32_t ret = CfOpensslCreateCert(&g_cert[1], nullptr); /* object is nullptr */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter create cert object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateCertTest009
 * @tc.desc: Test CertFramework adapter create and destory cert object interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest009, TestSize.Level0)
{
    for (uint32_t i = 0; i < PERFORMANCE_COUNT; ++i) { /* run 1000 times */
        CfBase *pemObj = nullptr;
        int32_t ret = CfOpensslCreateCert(&g_cert[0], &pemObj);
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;
        CfOpensslDestoryCert(&pemObj);
    }
}

/**
 * @tc.name: OpensslCreateCertTest010
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslCreateCertTest010, TestSize.Level0)
{
    CfBase *obj010 = nullptr;
    /* cert size don't match cert data */
    CfEncodingBlob invalCert010 = { const_cast<uint8_t *>(g_certData01), sizeof(g_certData01) - 1, CF_FORMAT_DER };
    int32_t ret = CfOpensslCreateCert(&invalCert010, &obj010);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) << "Abnormal adapter create cert object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslDestoryCertTest001
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslDestoryCertTest001, TestSize.Level0)
{
    CfBase **obj006 = nullptr; /* object is nullptr */
    CfOpensslDestoryCert(obj006);
}

/**
 * @tc.name: OpensslDestoryCertTest002
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslDestoryCertTest002, TestSize.Level0)
{
    CfBase *obj007 = nullptr; /* *object is nullptr */
    CfOpensslDestoryCert(&obj007);
}

/**
 * @tc.name: OpensslDestoryCertTest003
 * @tc.desc: Test CertFramework adapter create cert object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslDestoryCertTest003, TestSize.Level0)
{
    CfBase *obj008 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &obj008);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    obj008->type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION); /* object type error */
    CfOpensslDestoryCert(&obj008);

    obj008->type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT); /* normal case */
    CfOpensslDestoryCert(&obj008);
}

/**
 * @tc.name: OpensslDestoryCertTest004
 * @tc.desc: X509Cert is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslDestoryCertTest004, TestSize.Level0)
{
    CfBase *obj004 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &obj004);
    ASSERT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfOpensslCertObj *certObj = reinterpret_cast<CfOpensslCertObj *>(obj004);
    X509 *tmp = certObj->x509Cert;
    X509_free(tmp);

    certObj->x509Cert = nullptr;
    CfOpensslDestoryCert(&obj004);
}

/**
 * @tc.name: OpensslGetCertItemTest001
 * @tc.desc: Test CertFramework adapter get der cert extension interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest001, TestSize.Level0)
{
    CfBase *obj001 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &obj001); /* der format cert input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob extBlob001 = { 0, nullptr };
    ret = CfOpensslGetCertItem(obj001, CF_ITEM_EXTENSIONS, &extBlob001);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter pem get cert extension test failed, recode:" << ret;

    EXPECT_EQ(extBlob001.size, g_certExtension[0].size) << "The size of extension is wrong, test faield";
    ret = memcmp(extBlob001.data, g_certExtension[0].data, extBlob001.size);
    EXPECT_EQ(ret, 0) << "The data of extension is wrong, test faield";

    CF_FREE_BLOB(extBlob001);
    CfOpensslDestoryCert(&obj001);
}

/**
 * @tc.name: OpensslGetCertItemTest002
 * @tc.desc: Test CertFramework adapter get pem cert extension interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest002, TestSize.Level0)
{
    CfBase *obj002 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[1], &obj002); /* pem format cert input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob extBlob002 = { 0, nullptr };
    ret = CfOpensslGetCertItem(obj002, CF_ITEM_EXTENSIONS, &extBlob002);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get der cert extension test failed, recode:" << ret;

    EXPECT_EQ(extBlob002.size, g_certExtension[1].size) << "The size of extension is wrong, test faield";
    ret = memcmp(extBlob002.data, g_certExtension[1].data, extBlob002.size);
    EXPECT_EQ(ret, 0) << "The data of extension is wrong, test faield";

    CF_FREE_BLOB(extBlob002);
    CfOpensslDestoryCert(&obj002);
}

/**
 * @tc.name: OpensslGetCertItemTest003
 * @tc.desc: Test CertFramework adapter get cert item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest003, TestSize.Level0)
{
    CfBase *obj003 = nullptr;
    CfBlob extBlob003 = { 0, nullptr };
    int32_t ret = CfOpensslGetCertItem(obj003, CF_ITEM_EXTENSIONS, &extBlob003); /* object is nullptr */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter get cert item test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslGetCertItemTest004
 * @tc.desc: Test CertFramework adapter get cert item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest004, TestSize.Level0)
{
    CfBase *certObj004 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &certObj004); /* der format cert input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    certObj004->type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CRL); /* the type is invalid */

    CfBlob extBlob004 = { 0, nullptr };
    ret = CfOpensslGetCertItem(certObj004, CF_ITEM_EXTENSIONS, &extBlob004);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter get cert item test failed, recode:" << ret;

    certObj004->type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT);
    CfOpensslDestoryCert(&certObj004);
}

/**
 * @tc.name: OpensslGetCertItemTest005
 * @tc.desc: Test CertFramework adapter get cert item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest005, TestSize.Level0)
{
    /* the x509 is nullptr */
    const CfOpensslCertObj certObj005 = { {CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT)}, nullptr };
    CfBlob extBlob005 = { 0, nullptr };
    int32_t ret = CfOpensslGetCertItem(&(certObj005.base), CF_ITEM_EXTENSIONS, &extBlob005);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter get cert item test failed, recode:" << ret;
}

/**s
 * @tc.name: OpensslGetCertItemTest006
 * @tc.desc: Test CertFramework adapter get cert item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest006, TestSize.Level0)
{
    CfBase *certObj006 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &certObj006); /* der format cert input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob extBlob006 = { 0, nullptr };
    ret = CfOpensslGetCertItem(certObj006, CF_ITEM_INVALID, &extBlob006); /* the id is invalid */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter get cert item test failed, recode:" << ret;

    CfOpensslDestoryCert(&certObj006);
}

/**
 * @tc.name: OpensslGetCertItemTest007
 * @tc.desc: Test CertFramework adapter get cert item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest007, TestSize.Level0)
{
    CfBase *certObj007 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &certObj007); /* der format cert input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    ret = CfOpensslGetCertItem(certObj007, CF_ITEM_EXTENSIONS, nullptr); /* the outBlob is nullptr */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter get cert item test failed, recode:" << ret;

    CfOpensslDestoryCert(&certObj007);
}

/**
 * @tc.name: OpensslGetCertItemTest008
 * @tc.desc: Test CertFramework adapter get cert extension interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest008, TestSize.Level0)
{
    for (uint32_t i = 0; i < PERFORMANCE_COUNT; ++i) { /* run 1000 times */
        for (uint32_t j = 0; j < sizeof(g_cert) / sizeof(g_cert[0]); j++) {
            CfBase *certObj008 = nullptr;
            int32_t ret = CfOpensslCreateCert(&g_cert[j], &certObj008);
            EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed,"
                "index:" << j << " ,recode:" << ret;

            CfBlob extBlob008 = { 0, nullptr };
            ret = CfOpensslGetCertItem(certObj008, CF_ITEM_EXTENSIONS, &extBlob008);
            EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get cert extension test failed,"
                "index:" << j << " ,recode:" << ret;

            EXPECT_EQ(extBlob008.size, g_certExtension[j].size) << "The size is wrong, test faield, index = " << j;
            ret = memcmp(extBlob008.data, g_certExtension[j].data, extBlob008.size);
            EXPECT_EQ(ret, 0) << "The data of extension is wrong, test faield, index = " << j;

            CF_FREE_BLOB(extBlob008);
            CfOpensslDestoryCert(&certObj008);
        }
    }
}

/**
 * @tc.name: OpensslGetCertItemTest009
 * @tc.desc: Test CertFramework adapter get pem cert issuerUID interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest009, TestSize.Level0)
{
    CfBase *obj009 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &obj009); /* der format cert with issuerUID input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob extBlob009 = { 0, nullptr };
    ret = CfOpensslGetCertItem(obj009, CF_ITEM_ISSUER_UNIQUE_ID, &extBlob009);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get der cert issuerUID test failed, recode:" << ret;

    EXPECT_EQ(extBlob009.size, sizeof(g_certData01IssuerUID)) << "The size of issuerUID is wrong, test faield";
    ret = memcmp(extBlob009.data, g_certData01IssuerUID, extBlob009.size);
    EXPECT_EQ(ret, 0) << "The data of issuerUID is wrong, test faield";

    CF_FREE_BLOB(extBlob009);
    CfOpensslDestoryCert(&obj009);
}

/**
 * @tc.name: OpensslGetCertItemTest010
 * @tc.desc: Test CertFramework adapter get cert issuerUID interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest010, TestSize.Level0)
{
    CfBase *obj010 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[1], &obj010); /* pem format cert without issuerUID input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob extBlob010 = { 0, nullptr };
    ret = CfOpensslGetCertItem(obj010, CF_ITEM_ISSUER_UNIQUE_ID, &extBlob010);
    EXPECT_EQ(ret, CF_NOT_EXIST) << "Abnormal adapter get cert issuerUID test failed, recode:" << ret;

    CfOpensslDestoryCert(&obj010);
}

/**
 * @tc.name: OpensslGetCertItemTest011
 * @tc.desc: Test CertFramework adapter get cert issuerUID interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest011, TestSize.Level0)
{
    for (uint32_t i = 0; i < PERFORMANCE_COUNT; ++i) { /* run 1000 times */
        CfBase *obj011 = nullptr;
        int32_t ret = CfOpensslCreateCert(&g_cert[0], &obj011); /* der format cert with issuerUID input */
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

        CfBlob extBlob011 = { 0, nullptr };
        ret = CfOpensslGetCertItem(obj011, CF_ITEM_ISSUER_UNIQUE_ID, &extBlob011);
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get der cert issuerUID test failed, recode:" << ret;

        EXPECT_EQ(extBlob011.size, sizeof(g_certData01IssuerUID)) << "The size of issuerUID is wrong, test faield";
        ret = memcmp(extBlob011.data, g_certData01IssuerUID, extBlob011.size);
        EXPECT_EQ(ret, 0) << "The data of issuerUID is wrong, test faield";

        CF_FREE_BLOB(extBlob011);
        CfOpensslDestoryCert(&obj011);
    }
}

/**
 * @tc.name: OpensslGetCertItemTest012
 * @tc.desc: Test CertFramework adapter get pem cert subjectUID interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest012, TestSize.Level0)
{
    CfBase *obj012 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &obj012); /* Der format cert with subjectUID input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob extBlob012 = { 0, nullptr };
    ret = CfOpensslGetCertItem(obj012, CF_ITEM_SUBJECT_UNIQUE_ID, &extBlob012);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get der cert subjectUID test failed, recode:" << ret;

    EXPECT_EQ(extBlob012.size, sizeof(g_certData01SubjectUID)) << "The size of subjectUID is wrong, test faield";
    ret = memcmp(extBlob012.data, g_certData01SubjectUID, extBlob012.size);
    EXPECT_EQ(ret, 0) << "The data of subjectUID is wrong, test faield";

    CF_FREE_BLOB(extBlob012);
    CfOpensslDestoryCert(&obj012);
}

/**
 * @tc.name: OpensslGetCertItemTest013
 * @tc.desc: Test CertFramework adapter get cert subjectUID interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest013, TestSize.Level0)
{
    CfBase *obj013 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[1], &obj013); /* pem format cert without subjectUID input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob extBlob013 = { 0, nullptr };
    ret = CfOpensslGetCertItem(obj013, CF_ITEM_SUBJECT_UNIQUE_ID, &extBlob013);
    EXPECT_EQ(ret, CF_NOT_EXIST) << "Abnormal adapter get cert subjectUID test failed, recode:" << ret;

    CfOpensslDestoryCert(&obj013);
}

/**
 * @tc.name: OpensslGetCertItemTest014
 * @tc.desc: Test CertFramework adapter get cert subjectUID interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest014, TestSize.Level0)
{
    for (uint32_t i = 0; i < PERFORMANCE_COUNT; ++i) { /* run 1000 times */
        CfBase *obj014 = nullptr;
        int32_t ret = CfOpensslCreateCert(&g_cert[0], &obj014); /* Der format cert with subjectUID input */
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

        CfBlob extBlob014 = { 0, nullptr };
        ret = CfOpensslGetCertItem(obj014, CF_ITEM_SUBJECT_UNIQUE_ID, &extBlob014);
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get der cert subjectUID test failed, recode:" << ret;

        EXPECT_EQ(extBlob014.size, sizeof(g_certData01SubjectUID)) << "The size of subjectUID is wrong, test faield";
        ret = memcmp(extBlob014.data, g_certData01SubjectUID, extBlob014.size);
        EXPECT_EQ(ret, 0) << "The data of subjectUID is wrong, test faield";

        CF_FREE_BLOB(extBlob014);
        CfOpensslDestoryCert(&obj014);
    }
}

/**
 * @tc.name: OpensslGetCertItemTest015
 * @tc.desc: Test CertFramework adapter get der cert TBS interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest015, TestSize.Level0)
{
    CfBase *obj015 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &obj015); /* der format cert input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob extBlob015 = { 0, nullptr };
    ret = CfOpensslGetCertItem(obj015, CF_ITEM_TBS, &extBlob015);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get der cert TBS test failed, recode:" << ret;

    EXPECT_EQ(extBlob015.size, g_certTBS[0].size) << "The size of TBS is wrong, test faield";
    ret = memcmp(extBlob015.data, g_certTBS[0].data, extBlob015.size);
    EXPECT_EQ(ret, 0) << "The data of TBS is wrong, test faield";

    CF_FREE_BLOB(extBlob015);
    CfOpensslDestoryCert(&obj015);
}

/**
 * @tc.name: OpensslGetCertItemTest016
 * @tc.desc: Test CertFramework adapter get pem cert TBS interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest016, TestSize.Level0)
{
    CfBase *obj016 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[1], &obj016); /* pem format cert input */
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob extBlob016 = { 0, nullptr };
    ret = CfOpensslGetCertItem(obj016, CF_ITEM_TBS, &extBlob016);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get pem cert TBS test failed, recode:" << ret;

    EXPECT_EQ(extBlob016.size, g_certTBS[1].size) << "The size of TBS is wrong, test faield";
    ret = memcmp(extBlob016.data, g_certTBS[1].data, extBlob016.size);
    EXPECT_EQ(ret, 0) << "The data of TBS is wrong, test faield";

    CF_FREE_BLOB(extBlob016);
    CfOpensslDestoryCert(&obj016);
}

/**
 * @tc.name: OpensslGetCertItemTest017
 * @tc.desc: Test CertFramework adapter get cert TBS interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest017, TestSize.Level0)
{
    for (uint32_t i = 0; i < PERFORMANCE_COUNT; ++i) { /* run 1000 times */
        for (uint32_t j = 0; j < sizeof(g_cert) / sizeof(g_cert[0]); j++) {
            CfBase *certObj017 = nullptr;
            int32_t ret = CfOpensslCreateCert(&g_cert[j], &certObj017);
            EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed,"
                "index:" << j << " ,recode:" << ret;

            CfBlob extBlob017 = { 0, nullptr };
            ret = CfOpensslGetCertItem(certObj017, CF_ITEM_TBS, &extBlob017);
            EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get cert TBS test failed,"
                "index:" << j << " ,recode:" << ret;

            EXPECT_EQ(extBlob017.size, g_certTBS[j].size) << "The size is wrong, test faield, index = " << j;
            ret = memcmp(extBlob017.data, g_certTBS[j].data, extBlob017.size);
            EXPECT_EQ(ret, 0) << "The data of TBS is wrong, test faield, index = " << j;

            CF_FREE_BLOB(extBlob017);
            CfOpensslDestoryCert(&certObj017);
        }
    }
}

/**
 * @tc.name: OpensslGetCertItemTest018
 * @tc.desc: Test CertFramework adapter get cert public key
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAdapterCertTest, OpensslGetCertItemTest018, TestSize.Level0)
{
    CfBase *obj018 = nullptr;
    int32_t ret = CfOpensslCreateCert(&g_cert[0], &obj018);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create cert object test failed, recode:" << ret;

    CfBlob outBlob018 = { 0, nullptr };
    ret = CfOpensslGetCertItem(obj018, CF_ITEM_PUBLIC_KEY, &outBlob018);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter get public key test failed, recode:" << ret;

    CfBlob pubKey = { sizeof(g_certData01PubKey), const_cast<uint8_t *>(g_certData01PubKey) };
    EXPECT_EQ(CompareBlob(&outBlob018, &pubKey), true);

    CfFree(outBlob018.data);
    CfOpensslDestoryCert(&obj018);
}
}
