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
#include <openssl/x509v3.h>

#include "cf_adapter_extension_openssl.h"
#include "cf_test_common.h"
#include "cf_magic.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "cf_test_data.h"

using namespace testing::ext;
using namespace CertframeworkTest;
using namespace CertframeworkTestData;

namespace {
CfEncodingBlob g_extension[] = {
    { const_cast<uint8_t *>(g_extensionData01), sizeof(g_extensionData01), CF_FORMAT_DER },
    { const_cast<uint8_t *>(g_extensionData02), sizeof(g_extensionData02), CF_FORMAT_DER },
    { const_cast<uint8_t *>(g_extensionData03), sizeof(g_extensionData03), CF_FORMAT_DER },
    { const_cast<uint8_t *>(g_extensionTaintedData), sizeof(g_extensionTaintedData), CF_FORMAT_DER },
};

class CfAdapterExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CfAdapterExtensionTest::SetUpTestCase(void)
{
}

void CfAdapterExtensionTest::TearDownTestCase(void)
{
}

void CfAdapterExtensionTest::SetUp()
{
}

void CfAdapterExtensionTest::TearDown()
{
}

/**
 * @tc.name: OpensslCreateExtensionTest001
 * @tc.desc: Test CertFramework adapter create extension object interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCreateExtensionTest001, TestSize.Level0)
{
    CfBase *extsObj001 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &extsObj001);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfOpensslDestoryExtension(&extsObj001);
}

/**
 * @tc.name: OpensslCreateExtensionTest002
 * @tc.desc: Test CertFramework adapter create extension object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCreateExtensionTest002, TestSize.Level0)
{
    CfBase *extsObj002 = nullptr;
    CfEncodingBlob *invalidExts = nullptr; /* exts blob is null */
    int32_t ret = CfOpensslCreateExtension(invalidExts, &extsObj002);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter create extension object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateExtensionTest003
 * @tc.desc: Test CertFramework adapter create extension object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCreateExtensionTest003, TestSize.Level0)
{
    CfBase *extsObj003 = nullptr;
    CfEncodingBlob invalidExts = { nullptr, 10, CF_FORMAT_DER }; /* exts data is null */
    int32_t ret = CfOpensslCreateExtension(&invalidExts, &extsObj003);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter create extension object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateExtensionTest004
 * @tc.desc: Test CertFramework adapter create extension object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCreateExtensionTest004, TestSize.Level0)
{
    CfBase *extsObj004 = nullptr;
    CfEncodingBlob invalidExts = { const_cast<uint8_t *>(g_extensionData01), 0, CF_FORMAT_DER }; /* exts size is 0 */
    int32_t ret = CfOpensslCreateExtension(&invalidExts, &extsObj004);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter create extension object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateExtensionTest005
 * @tc.desc: Test CertFramework adapter create extension object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCreateExtensionTest005, TestSize.Level0)
{
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], nullptr);  /* object is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter create extension object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateExtensionTest006
 * @tc.desc: Test CertFramework adapter create extension object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCreateExtensionTest006, TestSize.Level0)
{
    CfBase *extsObj005 = nullptr;
    /* exts size don't match exts data */
    CfEncodingBlob invalidExts = {
        const_cast<uint8_t *>(g_extensionData01),
        sizeof(g_extensionData01) - 1,
        CF_FORMAT_DER
    };
    int32_t ret = CfOpensslCreateExtension(&invalidExts, &extsObj005);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) << "Abnormal adapter create extension object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateExtensionTest007
 * @tc.desc: Test CertFramework adapter create and destory extension object interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCreateExtensionTest007, TestSize.Level0)
{
    for (uint32_t i = 0; i < PERFORMANCE_COUNT; ++i) { /* run 1000 times */
        CfBase *extsObj006 = nullptr;
        int32_t ret = CfOpensslCreateExtension(&g_extension[1], &extsObj006);
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;
        CfOpensslDestoryExtension(&extsObj006);
    }
}

/**
 * @tc.name: OpensslCreateExtensionTest008
 * @tc.desc: Test CertFramework adapter create extension object interface abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCreateExtensionTest008, TestSize.Level0)
{
    CfBase *extsObj007 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[3], &extsObj007); /* tainted extension data */
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) << "Normal adapter create extension object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCreateExtensionTest009
 * @tc.desc: Test CertFramework adapter create extension object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCreateExtensionTest009, TestSize.Level0)
{
    CfBase *extsObj008 = nullptr;
    /* exts size beyond max */
    CfEncodingBlob invalidExts = { const_cast<uint8_t *>(g_extensionData01), MAX_LEN_EXTENSIONS + 1, CF_FORMAT_DER };
    int32_t ret = CfOpensslCreateExtension(&invalidExts, &extsObj008);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal adapter create extension object test failed, recode:" << ret;

    extsObj008 = nullptr;
    invalidExts.len = MAX_LEN_EXTENSIONS; /* exts size equal max */
    ret = CfOpensslCreateExtension(&invalidExts, &extsObj008);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) << "Abnormal adapter create extension object test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslDestoryExtensionTest001
 * @tc.desc: Test CertFramework adapter destory extension object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslDestoryExtensionTest001, TestSize.Level0)
{
    CfBase *obj001 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &obj001);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    obj001->type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT); /* object type error */
    CfOpensslDestoryExtension(&obj001);

    obj001->type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION); /* normal case */
    CfOpensslDestoryExtension(&obj001);
}

/**
 * @tc.name: OpensslDestoryExtensionTest002
 * @tc.desc: Test CertFramework adapter destory extension object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslDestoryExtensionTest002, TestSize.Level0)
{
    CfBase *obj002 = nullptr;  /* *object is null */
    CfOpensslDestoryExtension(&obj002);
}

/**
 * @tc.name: OpensslDestoryExtensionTest003
 * @tc.desc: Test CertFramework adapter destory extension object interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslDestoryExtensionTest003, TestSize.Level0)
{
    CfOpensslDestoryExtension(nullptr); /* object is null */
}

/**
 * @tc.name: OpensslGetOidsTest001
 * @tc.desc: Test CertFramework adapter extension object get all oids interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest001, TestSize.Level0)
{
    CfBase *object001 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &object001);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfBlobArray outArray = { nullptr, 0 };
    ret = CfOpensslGetOids(object001, CF_EXT_TYPE_ALL_OIDS, &outArray);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object get all oids test failed, recode:" << ret;

    EXPECT_EQ(true, CompareOidArray(&outArray, &g_expectAllOidArray)) << "The all oids obtained does not match";
    FreeCfBlobArray(outArray.data, outArray.count);

    CfOpensslDestoryExtension(&object001);
}

/**
 * @tc.name: OpensslGetOidsTest002
 * @tc.desc: Test CertFramework adapter extension object get critical oids interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest002, TestSize.Level0)
{
    CfBase *object002 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &object002);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfBlobArray outArray = { nullptr, 0 };
    ret = CfOpensslGetOids(object002, CF_EXT_TYPE_CRITICAL_OIDS, &outArray);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object get critical oids test failed, recode:" << ret;

    EXPECT_EQ(true, CompareOidArray(&outArray, &g_expectCritOidArray)) << "The critical oids obtained does not match";
    FreeCfBlobArray(outArray.data, outArray.count);

    CfOpensslDestoryExtension(&object002);
}

/**
 * @tc.name: OpensslGetOidsTest003
 * @tc.desc: Test CertFramework adapter extension object get uncritical oids interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest003, TestSize.Level0)
{
    CfBase *object003 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &object003);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfBlobArray outArray = { nullptr, 0 };
    ret = CfOpensslGetOids(object003, CF_EXT_TYPE_UNCRITICAL_OIDS, &outArray);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object get uncritical oids test failed, recode:" << ret;

    EXPECT_EQ(true, CompareOidArray(&outArray, &g_expectUncritOidArray)) <<
        "The uncritical oids obtained does not match";
    FreeCfBlobArray(outArray.data, outArray.count);

    CfOpensslDestoryExtension(&object003);
}

/**
 * @tc.name: OpensslGetOidsTest004
 * @tc.desc: Test CertFramework adapter extension object get oids interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest004, TestSize.Level0)
{
    CfBlobArray outArray = { nullptr, 0 };
    int32_t ret = CfOpensslGetOids(nullptr, CF_EXT_TYPE_ALL_OIDS, &outArray); /* object is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal exts object get all oids test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslGetOidsTest005
 * @tc.desc: Test CertFramework adapter extension object get oids interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest005, TestSize.Level0)
{
    CfBase object005 = { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) };
    int32_t ret = CfOpensslGetOids(&object005, CF_EXT_TYPE_ALL_OIDS, nullptr); /* out is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal exts object get all oids test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslGetOidsTest006
 * @tc.desc: Test CertFramework adapter extension object get oids interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest006, TestSize.Level0)
{
    CfOpensslExtensionObj exts = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT) }, nullptr };
    CfBase *object006 = &exts.base; /* object type is error */
    CfBlobArray outArray = { nullptr, 0 };
    int32_t ret = CfOpensslGetOids(object006, CF_EXT_TYPE_ALL_OIDS, &outArray);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal exts object get all oids test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslGetOidsTest007
 * @tc.desc: Test CertFramework adapter extension object get oids interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest007, TestSize.Level0)
{
    CfOpensslExtensionObj exts = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    CfBase *object007 = &exts.base; /* exts is null */
    CfBlobArray outArray = { nullptr, 0 };
    int32_t ret = CfOpensslGetOids(object007, CF_EXT_TYPE_ALL_OIDS, &outArray);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Abnormal exts object get all oids test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslGetOidsTest008
 * @tc.desc: Test CertFramework adapter extension object get oids interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest008, TestSize.Level0)
{
    CfOpensslExtensionObj exts = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    CfBase *object008 = &exts.base;
    CfBlobArray outArray = { nullptr, 0 };

    X509_EXTENSIONS *tmpExts008 = sk_X509_EXTENSION_new_null();
    sk_X509_EXTENSION_zero(tmpExts008);
    exts.exts = tmpExts008; /* exts is exist but no extension member */
    int32_t ret = CfOpensslGetOids(object008, CF_EXT_TYPE_ALL_OIDS, &outArray);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) << "Abnormal exts object get all oids test failed, recode:" << ret;

    sk_X509_EXTENSION_pop_free(tmpExts008, X509_EXTENSION_free);
}

/**
 * @tc.name: OpensslGetOidsTest009
 * @tc.desc: Test CertFramework adapter extension object get oids interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest009, TestSize.Level0)
{
    CfOpensslExtensionObj exts = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    CfBase *object009 = &exts.base;
    CfBlobArray outArray = { nullptr, 0 };

    X509_EXTENSIONS *tmpExts009 = sk_X509_EXTENSION_new_null();
    exts.exts = tmpExts009;
    sk_X509_EXTENSION_zero(tmpExts009);
    (void)sk_X509_EXTENSION_push(tmpExts009, nullptr); /* exts has one extension member, but data is null */
    int32_t ret = CfOpensslGetOids(object009, CF_EXT_TYPE_ALL_OIDS, &outArray);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) << "Abnormal exts object get all oids test failed, recode:" << ret;

    sk_X509_EXTENSION_pop_free(tmpExts009, X509_EXTENSION_free);
}

/**
 * @tc.name: OpensslGetOidsTest010
 * @tc.desc: Test CertFramework adapter extension object get oids interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest010, TestSize.Level0)
{
    CfBase *object010 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &object010);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfBlobArray outArray = { nullptr, 0 };
    /* extension type is undefined */
    ret = CfOpensslGetOids(object010, static_cast<CfExtensionOidType>(INT_MAX), &outArray);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) << "Normal adapter exts object get oids test failed, recode:" << ret;

    CfOpensslDestoryExtension(&object010);
}

/**
 * @tc.name: OpensslGetOidsTest011
 * @tc.desc: Test CertFramework adapter extension object get oids interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetOidsTest011, TestSize.Level0)
{
    CfBase *object011 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &object011);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    for (uint32_t i = 0; i < PERFORMANCE_COUNT; ++i) { /* run 1000 times */
        CfBlobArray outArray = { nullptr, 0 };

        ret = CfOpensslGetOids(object011, CF_EXT_TYPE_ALL_OIDS, &outArray);
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter exts object get all oids test failed, recode:" << ret;
        EXPECT_EQ(true, CompareOidArray(&outArray, &g_expectAllOidArray)) << "The all oids obtained does not match";
        FreeCfBlobArray(outArray.data, outArray.count);

        ret = CfOpensslGetOids(object011, CF_EXT_TYPE_CRITICAL_OIDS, &outArray);
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter exts object get critical oids test failed, recode:" << ret;
        EXPECT_EQ(true, CompareOidArray(&outArray, &g_expectCritOidArray)) <<
            "The critical oids obtained does not match";
        FreeCfBlobArray(outArray.data, outArray.count);

        ret = CfOpensslGetOids(object011, CF_EXT_TYPE_UNCRITICAL_OIDS, &outArray);
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter exts object get uncritical oids test failed, recode:" << ret;
        EXPECT_EQ(true, CompareOidArray(&outArray, &g_expectUncritOidArray)) <<
            "The uncritical oids obtained does not match";
        FreeCfBlobArray(outArray.data, outArray.count);
    }

    CfOpensslDestoryExtension(&object011);
}

/**
 * @tc.name: OpensslGetEntryTest001
 * @tc.desc: Test CertFramework adapter extension object get entry interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest001, TestSize.Level0)
{
    CfBase *obj001 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &obj001);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfBlob outBlob = { 0, nullptr };
    ret = CfOpensslGetEntry(obj001, CF_EXT_ENTRY_TYPE_ENTRY, &oid, &outBlob);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object get entry test failed, recode:" << ret;
    EXPECT_EQ(true, CompareBlob(&outBlob, &g_extensionEntryBlob01)) <<
        "Normal adapter extension object get entry test failed, get outBlob faield";
    CF_FREE_BLOB(outBlob);

    CfOpensslDestoryExtension(&obj001);
}

/**
 * @tc.name: OpensslGetEntryTest002
 * @tc.desc: Test CertFramework adapter extension object get entry crirical interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest002, TestSize.Level0)
{
    CfBase *obj002 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &obj002);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfBlob outBlob = { 0, nullptr };
    ret = CfOpensslGetEntry(obj002, CF_EXT_ENTRY_TYPE_ENTRY_CRITICAL, &oid, &outBlob);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object get entry crirical test failed, recode:" << ret;
    EXPECT_EQ(true, CompareBlob(&outBlob, &g_extensionEntryCriticalBlob01)) <<
        "Normal adapter extension object get entry test failed, get outBlob faield";
    CF_FREE_BLOB(outBlob);

    CfOpensslDestoryExtension(&obj002);
}

/**
 * @tc.name: OpensslGetEntryTest003
 * @tc.desc: Test CertFramework adapter extension object get entry value interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest003, TestSize.Level0)
{
    CfBase *obj003 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &obj003);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfBlob outBlob = { 0, nullptr };
    ret = CfOpensslGetEntry(obj003, CF_EXT_ENTRY_TYPE_ENTRY_VALUE, &oid, &outBlob);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object get entry value test failed, recode:" << ret;
    EXPECT_EQ(true, CompareBlob(&outBlob, &g_extensionEntryValueBlob01)) <<
        "Normal adapter extension object get entry test failed, get outBlob faield";
    CF_FREE_BLOB(outBlob);

    CfOpensslDestoryExtension(&obj003);
}

/**
 * @tc.name: OpensslGetEntryTest004
 * @tc.desc: Test CertFramework adapter extension object get entry interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest004, TestSize.Level0)
{
    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfBlob outBlob = { 0, nullptr };

    // the object is abnormal param
    int32_t ret = CfOpensslGetEntry(nullptr, CF_EXT_ENTRY_TYPE_ENTRY, &oid, &outBlob); /* object is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get entry test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslGetEntryTest005
 * @tc.desc: Test CertFramework adapter extension object get entry interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest005, TestSize.Level0)
{
    CfBase *obj005 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &obj005);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfBlob outBlob = { 0, nullptr };

    unsigned long correctType = obj005->type;
    obj005->type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT); /* object type error */
    ret = CfOpensslGetEntry(obj005, CF_EXT_ENTRY_TYPE_ENTRY, &oid, &outBlob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get entry test failed, recode:" << ret;

    obj005->type = correctType;
    CfOpensslDestoryExtension(&obj005);
}

/**
 * @tc.name: OpensslGetEntryTest006
 * @tc.desc: Test CertFramework adapter extension object get entry interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest006, TestSize.Level0)
{
    CfBase *obj006 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &obj006);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfBlob outBlob = { 0, nullptr };


    CfOpensslExtensionObj *extsObj = (CfOpensslExtensionObj *)obj006;
    X509_EXTENSIONS *correctExts = extsObj->exts;
    extsObj->exts = nullptr; /* exts data is nullptr */
    ret = CfOpensslGetEntry(obj006, CF_EXT_ENTRY_TYPE_ENTRY, &oid, &outBlob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get entry test failed, recode:" << ret;

    extsObj->exts = correctExts;
    CfOpensslDestoryExtension(&obj006);
}

/**
 * @tc.name: OpensslGetEntryTest007
 * @tc.desc: Test CertFramework adapter extension object get entry interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest007, TestSize.Level0)
{
    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfBlob outBlob = { 0, nullptr };

    CfOpensslExtensionObj exts007 = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    X509_EXTENSIONS *tmpExts007 = sk_X509_EXTENSION_new_null();
    exts007.exts = tmpExts007; /* exts is exist but no extension member */
    sk_X509_EXTENSION_zero(tmpExts007);
    int32_t ret = CfOpensslGetEntry(&(exts007.base), CF_EXT_ENTRY_TYPE_ENTRY, &oid, &outBlob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) <<
        "Abnormal adapter extension object get entry test failed, recode:" << ret;

    sk_X509_EXTENSION_pop_free(tmpExts007, X509_EXTENSION_free);
}

/**
 * @tc.name: OpensslGetEntryTest008
 * @tc.desc: Test CertFramework adapter extension object get entry interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest008, TestSize.Level0)
{
    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfBlob outBlob = { 0, nullptr };

    CfOpensslExtensionObj exts008 = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    X509_EXTENSIONS *tmpExts008 = sk_X509_EXTENSION_new_null();
    exts008.exts = tmpExts008;
    sk_X509_EXTENSION_zero(tmpExts008);
    (void)sk_X509_EXTENSION_push(tmpExts008, nullptr); /* exts has one extension member, but data is null */
    int32_t ret = CfOpensslGetEntry(&(exts008.base), CF_EXT_ENTRY_TYPE_ENTRY, &oid, &outBlob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) <<
        "Abnormal adapter extension object get entry test5 failed, recode:" << ret;

    sk_X509_EXTENSION_pop_free(tmpExts008, X509_EXTENSION_free);
}

/**
 * @tc.name: OpensslGetEntryTest008
 * @tc.desc: Test CertFramework adapter extension object get entry interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest009, TestSize.Level0)
{
    CfBase *obj009 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &obj009);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfBlob outBlob = { 0, nullptr };

    CfExtensionEntryType errorType = static_cast<CfExtensionEntryType>(INT_MAX);
    ret = CfOpensslGetEntry(obj009, errorType, &oid, &outBlob); /* type is error */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get entry test failed, recode:" << ret;

    CfOpensslDestoryExtension(&obj009);
}

/**
 * @tc.name: OpensslGetEntryTest010
 * @tc.desc: Test CertFramework adapter extension object get entry interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest010, TestSize.Level0)
{
    CfBase *obj010 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &obj010);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfBlob outBlob = { 0, nullptr };
    // the oid is abnormal param
    ret = CfOpensslGetEntry(nullptr, CF_EXT_ENTRY_TYPE_ENTRY, nullptr, &outBlob); /* oid is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get entry test1 failed, recode:" << ret;

    char oidStr[] = "2.5.29.19";
    char oidErrStr1[] = "errorFormatData";
    char oidErrStr2[] = "2.5.29.20";
    CfBlob errorOidArray[] = {
        { strlen(oidStr), nullptr },                                        /* oid data is null */
        { 0, reinterpret_cast<uint8_t *>(oidStr) },                             /* the size of oid data is 0 */
        { MAX_LEN_OID + 1, reinterpret_cast<uint8_t *>(oidStr) },               /* the size of oid data is too larger */
        { strlen(oidErrStr1), reinterpret_cast<uint8_t *>(oidErrStr1) },    /* oid data is wrong */
        { strlen(oidErrStr2), reinterpret_cast<uint8_t *>(oidErrStr2) },    /* oid data is no include in exts */
    };
    int32_t expectRet[] = { CF_INVALID_PARAMS, CF_INVALID_PARAMS, CF_INVALID_PARAMS,
                            CF_INVALID_PARAMS, CF_NOT_EXIST };
    for (uint32_t i = 0; i < sizeof(errorOidArray) / sizeof(errorOidArray[0]); ++i) {
        CfBlob tmpOutBlob = { 0, nullptr };
        ret = CfOpensslGetEntry(obj010, CF_EXT_ENTRY_TYPE_ENTRY, &(errorOidArray[i]), &tmpOutBlob);
        EXPECT_EQ(ret, expectRet[i]) <<
            "Abnormal adapter extension object get entry test2 failed, index:," << i << " retcode:" << ret;
    }

    CfOpensslDestoryExtension(&obj010);
}

/**
 * @tc.name: OpensslGetEntryTest011
 * @tc.desc: Test CertFramework adapter extension object get entry interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest011, TestSize.Level0)
{
    CfBase *obj011 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &obj011);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    ret = CfOpensslGetEntry(obj011, CF_EXT_ENTRY_TYPE_ENTRY_VALUE, &oid, nullptr); /* outBlob is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get entry test failed, recode:" << ret;

    CfOpensslDestoryExtension(&obj011);
}

/**
 * @tc.name: OpensslGetEntryTest012
 * @tc.desc: Test CertFramework adapter extension object get entry interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetEntryTest012, TestSize.Level0)
{
    CfBase *obj012 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[0], &obj012);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };
    CfExtensionEntryType typeArray[] = {
        CF_EXT_ENTRY_TYPE_ENTRY,
        CF_EXT_ENTRY_TYPE_ENTRY_CRITICAL,
        CF_EXT_ENTRY_TYPE_ENTRY_VALUE,
    };

    for (uint32_t i = 0; i < sizeof(typeArray) / sizeof(typeArray[0]); ++i) {
        for (uint32_t j = 0; j < PERFORMANCE_COUNT; ++j) { /* run 1000 times */
            CfBlob outBlob = { 0, nullptr };
            ret = CfOpensslGetEntry(obj012, typeArray[i], &oid, &outBlob);
            EXPECT_EQ(ret, CF_SUCCESS) <<
                "Normal adapter extension object get entry test failed,  index:," << i << "recode:" << ret;
            CF_FREE_BLOB(outBlob);
        }
    }

    CfOpensslDestoryExtension(&obj012);
}

/**
 * @tc.name: OpensslCheckCATest001
 * @tc.desc: Test CertFramework adapter extension object check CA interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest001, TestSize.Level0)
{
    CfEncodingBlob extsArray[] = { g_extension[0], g_extension[1], g_extension[2] };
    int32_t expectPathLenArray[] = {
        BASIC_CONSTRAINTS_PATHLEN_NO_LIMIT, BASIC_CONSTRAINTS_PATHLEN_NO_LIMIT, 2 /* the 2 is the expect length */
    };

    for (uint32_t i = 0; i < sizeof(extsArray) / sizeof(extsArray[0]); ++i) {
        CfBase *extsObj001 = nullptr;
        int32_t ret = CfOpensslCreateExtension(&extsArray[i], &extsObj001);
        EXPECT_EQ(ret, CF_SUCCESS) <<
            "Normal adapter create extension object test1 failed, index:" << i << ", ret:" << ret;

        int32_t pathLen = 0;
        ret = CfOpensslCheckCA(extsObj001, &pathLen);
        EXPECT_EQ(ret, CF_SUCCESS) <<
            "Normal adapter extension object check CA test2 failed, index:" << i << ", ret:" << ret;
        EXPECT_EQ(pathLen, expectPathLenArray[i]) <<
            "Normal adapter extension object check CA test2 failed, index:" << i << ", pathLen:" << pathLen;
        CfOpensslDestoryExtension(&extsObj001);
    }
}

/**
 * @tc.name: OpensslCheckCATest002
 * @tc.desc: Test CertFramework adapter extension object check CA interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest002, TestSize.Level0)
{
    int32_t pathLen = 0;
    CfOpensslExtensionObj exts002 = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    X509_EXTENSIONS *tmpExts002 = sk_X509_EXTENSION_new_null();
    sk_X509_EXTENSION_zero(tmpExts002);
    exts002.exts = tmpExts002;

    uint8_t data[] = "1"; // the length of keyUsage is 1 and can pass no CA check
    ASN1_BIT_STRING bitStr = { strlen(reinterpret_cast<char *>(data)), V_ASN1_BIT_STRING, data, 0 };
    X509_EXTENSION *keyUsageExt = X509V3_EXT_i2d(NID_key_usage, 0, reinterpret_cast<void *>(&bitStr));

    (void)sk_X509_EXTENSION_push(tmpExts002, keyUsageExt);
    int32_t ret = CfOpensslCheckCA(&(exts002.base), &pathLen);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object check CA test failed, recode:" << ret;
    EXPECT_EQ(pathLen, BASIC_CONSTRAINTS_NO_CA) << "Normal test failed, not get the expected return value.";
    (void)sk_X509_EXTENSION_pop(tmpExts002);
    X509_EXTENSION_free(keyUsageExt);

    sk_X509_EXTENSION_pop_free(tmpExts002, X509_EXTENSION_free);
}

/**
 * @tc.name: OpensslCheckCATest003
 * @tc.desc: Test CertFramework adapter extension object check CA interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest003, TestSize.Level0)
{
    int32_t pathLen = 0;
    CfOpensslExtensionObj exts003 = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    X509_EXTENSIONS *tmpExts003 = sk_X509_EXTENSION_new_null();
    sk_X509_EXTENSION_zero(tmpExts003);
    exts003.exts = tmpExts003;

    uint8_t data[] = "test"; // the length of keyUsage is over 1 and can pass CA check
    ASN1_BIT_STRING bitStr = { strlen(reinterpret_cast<char *>(data)), V_ASN1_BIT_STRING, data, 0 };
    X509_EXTENSION *keyUsageExt = X509V3_EXT_i2d(NID_key_usage, 0, reinterpret_cast<void *>(&bitStr));
    (void)sk_X509_EXTENSION_push(tmpExts003, keyUsageExt);

    BASIC_CONSTRAINTS basic = { .ca = 0, .pathlen = nullptr }; // the 0 indicates that it is a CA
    X509_EXTENSION *basicConExt = X509V3_EXT_i2d(NID_basic_constraints, 0, reinterpret_cast<void *>(&basic));
    (void)sk_X509_EXTENSION_push(tmpExts003, basicConExt);

    int32_t ret = CfOpensslCheckCA(&(exts003.base), &pathLen);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object check CA test failed, recode:" << ret;
    EXPECT_EQ(pathLen, BASIC_CONSTRAINTS_NO_CA) << "Normal test failed, not get the expected return value.";

    (void)sk_X509_EXTENSION_pop(tmpExts003);
    (void)sk_X509_EXTENSION_pop(tmpExts003);
    X509_EXTENSION_free(basicConExt);
    X509_EXTENSION_free(keyUsageExt);
    sk_X509_EXTENSION_pop_free(tmpExts003, X509_EXTENSION_free);
}

/**
 * @tc.name: OpensslCheckCATest004
 * @tc.desc: Test CertFramework adapter extension object check CA interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest004, TestSize.Level0)
{
    int32_t pathLen = 0;
    CfOpensslExtensionObj exts004 = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    X509_EXTENSIONS *tmpExts004 = sk_X509_EXTENSION_new_null();
    sk_X509_EXTENSION_zero(tmpExts004);
    exts004.exts = tmpExts004;

    uint8_t data2[] = "test"; // the length of keyUsage is over 1 and can pass CA check
    ASN1_BIT_STRING bitStr = { strlen(reinterpret_cast<char *>(data2)), V_ASN1_BIT_STRING, data2, 0 };
    X509_EXTENSION *keyUsageExt = X509V3_EXT_i2d(NID_key_usage, 0, reinterpret_cast<void *>(&bitStr));
    (void)sk_X509_EXTENSION_push(tmpExts004, keyUsageExt);

    BASIC_CONSTRAINTS basic = { .ca = 1, .pathlen = nullptr }; // the 1 indicates that it is a CA
    X509_EXTENSION *basicConExt = X509V3_EXT_i2d(NID_basic_constraints, 0, reinterpret_cast<void *>(&basic));
    (void)sk_X509_EXTENSION_push(tmpExts004, basicConExt);

    int32_t ret = CfOpensslCheckCA(&(exts004.base), &pathLen);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object check CA test failed, recode:" << ret;
    EXPECT_EQ(pathLen, BASIC_CONSTRAINTS_PATHLEN_NO_LIMIT) <<
        "Normal test failed, not get the expected return value.";

    (void)sk_X509_EXTENSION_pop(tmpExts004);
    (void)sk_X509_EXTENSION_pop(tmpExts004);
    X509_EXTENSION_free(basicConExt);
    X509_EXTENSION_free(keyUsageExt);
    sk_X509_EXTENSION_pop_free(tmpExts004, X509_EXTENSION_free);
}

/**
 * @tc.name: OpensslCheckCATest005
 * @tc.desc: Test CertFramework adapter extension object check CA interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest005, TestSize.Level0)
{
    int32_t pathLen = 0;
    int32_t ret = CfOpensslCheckCA(nullptr, &pathLen); /* object is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object check CA test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCheckCATest006
 * @tc.desc: Test CertFramework adapter extension object check CA interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest006, TestSize.Level0)
{
    CfBase *extsObj006 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &extsObj006);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    int32_t pathLen = 0;
    unsigned long correctType = extsObj006->type;
    extsObj006->type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT); /* object type error */
    ret = CfOpensslCheckCA(extsObj006, &pathLen);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object check CA test failed, recode:" << ret;

    extsObj006->type = correctType;
    CfOpensslDestoryExtension(&extsObj006);
}

/**
 * @tc.name: OpensslCheckCATest007
 * @tc.desc: Test CertFramework adapter extension object check CA interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest007, TestSize.Level0)
{
    int32_t pathLen = 0;
    /* exts data is nullptr */
    CfOpensslExtensionObj exts007 = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    int32_t ret = CfOpensslCheckCA(&(exts007.base), &pathLen);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object check CA test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCheckCATest008
 * @tc.desc: Test CertFramework adapter extension object check CA interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest008, TestSize.Level0)
{
    int32_t pathLen = 0;
    CfOpensslExtensionObj exts008 = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };

    X509_EXTENSIONS *tmpExts008 = sk_X509_EXTENSION_new_null();
    sk_X509_EXTENSION_zero(tmpExts008);
    exts008.exts = tmpExts008; /* exts is exist but no extension member */
    int32_t ret = CfOpensslCheckCA(&(exts008.base), &pathLen);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) << "Abnormal adapter extension object check CA test failed, recode:" << ret;

    sk_X509_EXTENSION_pop_free(tmpExts008, X509_EXTENSION_free);
}

/**
 * @tc.name: OpensslCheckCATest009
 * @tc.desc: Test CertFramework adapter extension object check CA interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest009, TestSize.Level0)
{
    int32_t pathLen = 0;
    CfOpensslExtensionObj exts009 = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    X509_EXTENSIONS *tmpExts009 = sk_X509_EXTENSION_new_null();
    sk_X509_EXTENSION_zero(tmpExts009);
    exts009.exts = tmpExts009;

    uint8_t data[] = "test"; // the length of keyUsage is over 1 and can pass CA check, but no basic constraints
    ASN1_BIT_STRING bitStr = { strlen(reinterpret_cast<char *>(data)), V_ASN1_BIT_STRING, data, 0 };
    X509_EXTENSION *keyUsageExt = X509V3_EXT_i2d(NID_key_usage, 0, reinterpret_cast<void *>(&bitStr));

    (void)sk_X509_EXTENSION_push(tmpExts009, keyUsageExt);
    int32_t ret = CfOpensslCheckCA(&(exts009.base), &pathLen);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) <<
        "Abnormal adapter extension object check CA test4 failed, recode:" << ret;
    (void)sk_X509_EXTENSION_pop(tmpExts009);
    X509_EXTENSION_free(keyUsageExt);

    sk_X509_EXTENSION_pop_free(tmpExts009, X509_EXTENSION_free);
}

/**
 * @tc.name: OpensslCheckCATest010
 * @tc.desc: Test CertFramework adapter extension object check CA interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest010, TestSize.Level0)
{
    CfOpensslExtensionObj exts010 = { { CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION) }, nullptr };
    int32_t ret = CfOpensslCheckCA(&(exts010.base), nullptr); /* pathLen is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object check CA test failed, recode:" << ret;
}

/**
 * @tc.name: OpensslCheckCATest011
 * @tc.desc: Test CertFramework adapter extension object check CA interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslCheckCATest011, TestSize.Level0)
{
    CfBase *extsObj011 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &extsObj011);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    for (uint32_t i = 0; i < PERFORMANCE_COUNT; ++i) { /* run 1000 times */
        int32_t pathLen = 0;
        ret = CfOpensslCheckCA(extsObj011, &pathLen);
        EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object check CA  test failed, recode:" << ret;
    }

    CfOpensslDestoryExtension(&extsObj011);
}

/**
 * @tc.name: OpensslGetExtensionItemTest001
 * @tc.desc: Test CertFramework adapter extension object get extension item interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetExtensionItemTest001, TestSize.Level0)
{
    CfBase *obj001 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[1], &obj001);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfBlob blob = {g_extension[1].len, g_extension[1].data};
    CfBlob outBlob = { 0, nullptr };
    ret = CfOpensslGetExtensionItem(obj001, CF_ITEM_ENCODED, &outBlob);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter extension object get extension encoded  test failed, recode:" << ret;
    EXPECT_EQ(true, CompareBlob(&outBlob, &blob)) <<
        "Normal adapter extension object get extension encoded test failed, get outBlob faield";
    CF_FREE_BLOB(outBlob);
    CfOpensslDestoryExtension(&obj001);
}

/**
 * @tc.name: OpensslGetExtensionItemTest002
 * @tc.desc: Test CertFramework adapter extension object get extension item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetExtensionItemTest002, TestSize.Level0)
{
    CfBase *obj002 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[1], &obj002);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfBlob outBlob = { 0, nullptr };
    ret = CfOpensslGetExtensionItem(obj002, CF_ITEM_PUBLIC_KEY, &outBlob); /* id is invalid */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get extension encoded  test failed, recode:" << ret;

    CF_FREE_BLOB(outBlob);
    CfOpensslDestoryExtension(&obj002);
}

/**
 * @tc.name: OpensslGetExtensionItemTest003
 * @tc.desc: Test CertFramework adapter extension object get extension item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetExtensionItemTest003, TestSize.Level0)
{
    CfBase *obj003 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[1], &obj003);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    ret = CfOpensslGetExtensionItem(obj003, CF_ITEM_ENCODED, nullptr); /* outBlob is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get extension encoded  test failed, recode:" << ret;

    CfOpensslDestoryExtension(&obj003);
}

/**
 * @tc.name: OpensslGetExtensionItemTest004
 * @tc.desc: Test CertFramework adapter extension object get extension item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetExtensionItemTest004, TestSize.Level0)
{
    CfBlob outBlob = { 0, nullptr };
    int32_t ret = CfOpensslGetExtensionItem(nullptr, CF_ITEM_ENCODED, &outBlob); /* object is null */
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get extension encoded  test failed, recode:" << ret;
    CF_FREE_BLOB(outBlob);
}

/**
 * @tc.name: OpensslGetExtensionItemTest005
 * @tc.desc: Test CertFramework adapter extension object get extension item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetExtensionItemTest005, TestSize.Level0)
{
    CfBase *obj005 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[1], &obj005);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    unsigned long correctType = obj005->type;
    obj005->type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT); /* object type error */

    CfBlob outBlob = { 0, nullptr };
    ret = CfOpensslGetExtensionItem(obj005, CF_ITEM_ENCODED, &outBlob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get extension encoded  test failed, recode:" << ret;

    CF_FREE_BLOB(outBlob);
    obj005->type = correctType;
    CfOpensslDestoryExtension(&obj005);
}

/**
 * @tc.name: OpensslGetExtensionItemTest006
 * @tc.desc: Test CertFramework adapter extension object get extension item interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetExtensionItemTest006, TestSize.Level0)
{
    CfBase *obj006 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[1], &obj006);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfOpensslExtensionObj *extsObj = (CfOpensslExtensionObj *)obj006;
    X509_EXTENSIONS *exts = extsObj->exts;
    extsObj->exts = nullptr; /* exts is null */

    CfBlob outBlob = { 0, nullptr };
    ret = CfOpensslGetExtensionItem(obj006, CF_ITEM_ENCODED, &outBlob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object get extension encoded test failed, recode:" << ret;

    CF_FREE_BLOB(outBlob);
    extsObj->exts = exts;
    CfOpensslDestoryExtension(&obj006);
}

/**
 * @tc.name: OpensslGetExtensionItemTest007
 * @tc.desc: Test CertFramework adapter extension object get extension item interface performance
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslGetExtensionItemTest007, TestSize.Level0)
{
    CfBase *obj007 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[1], &obj007);
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, recode:" << ret;

    CfBlob blob = {g_extension[1].len, g_extension[1].data};

    for (uint32_t i = 0; i < PERFORMANCE_COUNT; ++i) { /* run 1000 times */
        CfBlob outBlob = { 0, nullptr };
        ret = CfOpensslGetExtensionItem(obj007, CF_ITEM_ENCODED, &outBlob);
        EXPECT_EQ(ret, CF_SUCCESS) <<
            "Normal adapter extension object get extension encoded  test failed, recode:" << ret;
        EXPECT_EQ(true, CompareBlob(&outBlob, &blob)) <<
            "Normal adapter extension object get extension encoded test failed, get outBlob faield";
        CF_FREE_BLOB(outBlob);
    }

    CfOpensslDestoryExtension(&obj007);
}

/**
 * @tc.name: OpensslHasUnsupportedCriticalExtensionTest001
 * @tc.desc: Test CertFramework adapter extension object has unsupported critical extension interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslHasUnsupportedCriticalExtensionTest001, TestSize.Level0)
{
    CfBase *obj001 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[1], &obj001);
    bool bRet = false;
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, retcode:" << ret;

    ret = CfOpensslHasUnsupportedCriticalExtension(nullptr, &bRet);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object has unsupported critical extension test failed, recode:" << ret;

    CfOpensslDestoryExtension(&obj001);
}

/**
 * @tc.name: OpensslHasUnsupportedCriticalExtensionTest002
 * @tc.desc: Test CertFramework adapter extension object has unsupported critical extension interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslHasUnsupportedCriticalExtensionTest002, TestSize.Level0)
{
    CfBase *obj002 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &obj002);
    bool bRet = false;
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, rectode:" << ret;

    CfOpensslExtensionObj *extsObj = (CfOpensslExtensionObj *)obj002;
    X509_EXTENSIONS *exts = extsObj->exts;

    uint8_t data[] = "test";
    ASN1_BIT_STRING bitStr = { strlen(reinterpret_cast<char *>(data)), V_ASN1_BIT_STRING, data, 0 };
    X509_EXTENSION *netscapeCommentExt = X509V3_EXT_i2d(NID_netscape_comment, 1, reinterpret_cast<void *>(&bitStr));

    (void)sk_X509_EXTENSION_push(exts, netscapeCommentExt);

    ret = CfOpensslHasUnsupportedCriticalExtension(obj002, &bRet);
    EXPECT_EQ(ret, CF_SUCCESS) <<
        "Abnormal adapter extension object has unsupported critical extension test failed, retcode:" << ret;
    EXPECT_EQ(bRet, true);

    (void)sk_X509_EXTENSION_pop(exts);
    X509_EXTENSION_free(netscapeCommentExt);
    CfOpensslDestoryExtension(&obj002);
}

/**
 * @tc.name: OpensslHasUnsupportedCriticalExtensionTest003
 * @tc.desc: Test CertFramework adapter extension object has unsupported critical extension interface Abnormal function
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslHasUnsupportedCriticalExtensionTest003, TestSize.Level0)
{
    CfBase *obj003 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[1], &obj003);
    bool bRet = false;
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, retcode:" << ret;

    CfOpensslExtensionObj *extsObj = (CfOpensslExtensionObj *)obj003;
    X509_EXTENSIONS *exts = extsObj->exts;
    extsObj->exts = nullptr; /* exts is null */

    ret = CfOpensslHasUnsupportedCriticalExtension(obj003, &bRet);
    EXPECT_EQ(ret, CF_INVALID_PARAMS) <<
        "Abnormal adapter extension object has unsupported critical extension test failed, retcode:" << ret;
    EXPECT_EQ(bRet, false);

    extsObj->exts = exts;
    CfOpensslDestoryExtension(&obj003);
}

/**
 * @tc.name: OpensslHasUnsupportedCriticalExtensionTest004
 * @tc.desc: Test CertFramework adapter extension object has unsupported critical extension,
 * While the extension number is more than MAX_COUNT_OID.
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfAdapterExtensionTest, OpensslHasUnsupportedCriticalExtensionTest004, TestSize.Level0)
{
    CfBase *obj004 = nullptr;
    int32_t ret = CfOpensslCreateExtension(&g_extension[2], &obj004);
    bool bRet = false;
    EXPECT_EQ(ret, CF_SUCCESS) << "Normal adapter create extension object test failed, rectode:" << ret;

    CfOpensslExtensionObj *extsObj = (CfOpensslExtensionObj *)obj004;
    X509_EXTENSIONS *exts = extsObj->exts;

    for (int index = 0; index < MAX_COUNT_OID + 1; index++) {
        string data = "test" + std::to_string(index);
        ASN1_BIT_STRING bitStr = { data.length(), V_ASN1_BIT_STRING,
            const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(data.c_str())), 0 };
        X509_EXTENSION *netscapeCommentExt = X509V3_EXT_i2d(NID_netscape_comment, 1, reinterpret_cast<void *>(&bitStr));

        (void)sk_X509_EXTENSION_push(exts, netscapeCommentExt);
    }

    ret = CfOpensslHasUnsupportedCriticalExtension(obj004, &bRet);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION) <<
        "Abnormal adapter extension object has unsupported critical extension test failed, retcode:" << ret;

    (void)sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    extsObj->exts = nullptr;
    CfOpensslDestoryExtension(&obj004);
}
}