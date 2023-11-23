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

#include "cf_type.h"

#include "cf_api.h"
#include "cf_param.h"
#include "cf_result.h"

#include "cf_test_data.h"
#include "cf_test_common.h"
#include "cf_test_sdk_common.h"

using namespace testing::ext;
using namespace CertframeworkTestData;
using namespace CertframeworkTest;
using namespace CertframeworkSdkTest;

namespace {
class CfExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CfExtensionTest::SetUpTestCase(void)
{
}

void CfExtensionTest::TearDownTestCase(void)
{
}

void CfExtensionTest::SetUp()
{
}

void CfExtensionTest::TearDown()
{
}

const static CfEncodingBlob g_extensionBlob[] = {
    { const_cast<uint8_t *>(g_extensionData03), sizeof(g_extensionData03), CF_FORMAT_DER }
};

const static CfBlob g_extEncoded = { sizeof(g_extensionData03), const_cast<uint8_t *>(g_extensionData03) };
const static int32_t g_expectPathLen = 2;

static int32_t CheckAndGetParam(CfTagType type, CfTag typeTag, const CfParamSet *paramSet, CfParam **param)
{
    CfParam *resultTypeParam = NULL;
    int32_t ret = CfGetParam(paramSet, CF_TAG_RESULT_TYPE, &resultTypeParam);
    if (ret != CF_SUCCESS) {
        printf("ext: get CF_TAG_RESULT_TYPE failed.\n");
        return ret;
    }

    if (resultTypeParam->int32Param != type) {
        printf("ext: result type is not CF_TAG_TYPE_BYTES.\n");
        return CF_INVALID_PARAMS;
    }

    ret = CfGetParam(paramSet, typeTag, param);
    if (ret != CF_SUCCESS) {
        printf("ext: get CF_TAG_RESULT_BYTES from out failed.\n");
        return ret;
    }

    return CF_SUCCESS;
}

static bool CompareItemResult(const CfParamSet *paramSet)
{
    CfParam *resultParam = NULL;
    int32_t ret = CheckAndGetParam(CF_TAG_TYPE_BYTES, CF_TAG_RESULT_BYTES, paramSet, &resultParam);
    if (ret != CF_SUCCESS) {
        return false;
    }
    return CompareBlob(&resultParam->blob, &g_extEncoded);
}

static bool CompareArray(const CfBlobArray *array, const CfParamSet *paramSet)
{
    if (array->count != paramSet->paramsCnt - 1) { /* paramSet has 1 result type param */
        printf("count not equal.\n");
        return false;
    }

    for (uint32_t i = 0; i < array->count; i++) {
        if (paramSet->params[i + 1].tag != CF_TAG_RESULT_BYTES) {
            printf("tag not bytes.\n");
            return false;
        }
        if (CompareBlob(&array->data[i], &paramSet->params[i + 1].blob) != true) {
            printf("blob data not equal.\n");
            return false;
        }
    }
    return true;
}

static bool CompareOidsResult(int32_t typeValue, const CfParamSet *paramSet)
{
    CfParam *resultParam = NULL;
    int32_t ret = CheckAndGetParam(CF_TAG_TYPE_BYTES, CF_TAG_RESULT_BYTES, paramSet, &resultParam);
    if (ret != CF_SUCCESS) {
        return false;
    }

    switch (typeValue) {
        case CF_EXT_TYPE_ALL_OIDS:
            return CompareArray(&g_expectAllOidArray, paramSet);
        case CF_EXT_TYPE_CRITICAL_OIDS:
            return CompareArray(&g_expectCritOidArray, paramSet);
        case CF_EXT_TYPE_UNCRITICAL_OIDS:
            return CompareArray(&g_expectUncritOidArray, paramSet);
        default:
            return false;
    }
}

static bool CompareEntryResult(int32_t typeValue, const CfParamSet *paramSet)
{
    CfParam *resultParam = NULL;
    int32_t ret = CheckAndGetParam(CF_TAG_TYPE_BYTES, CF_TAG_RESULT_BYTES, paramSet, &resultParam);
    if (ret != CF_SUCCESS) {
        return false;
    }

    switch (typeValue) {
        case CF_EXT_ENTRY_TYPE_ENTRY:
            return CompareBlob(&resultParam->blob, &g_extensionEntryBlob03);
        case CF_EXT_ENTRY_TYPE_ENTRY_CRITICAL:
            return CompareBlob(&resultParam->blob, &g_extensionEntryCriticalBlob03);
        case CF_EXT_ENTRY_TYPE_ENTRY_VALUE:
            return CompareBlob(&resultParam->blob, &g_extensionEntryValueBlob03);
        default:
            return false;
    }
}

static bool CompareCheckResult(const CfParamSet *paramSet)
{
    CfParam *resultParam = NULL;
    int32_t ret = CheckAndGetParam(CF_TAG_TYPE_INT, CF_TAG_RESULT_INT, paramSet, &resultParam);
    if (ret != CF_SUCCESS) {
        return false;
    }
    return (resultParam->int32Param == g_expectPathLen);
}

static void ExtensionTest(int32_t type, int32_t typeValue, const CfParam *params, uint32_t cnt)
{
    CfParamSet *outParamSet = nullptr;
    int32_t ret = CommonTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0], params, cnt, &outParamSet);
    EXPECT_EQ(ret, CF_SUCCESS);

#ifdef TEST_PRINT_DATA
    (void)GetOutValue(outParamSet);
#endif

    switch (type) {
        case CF_GET_TYPE_EXT_ITEM:
            EXPECT_EQ(CompareItemResult(outParamSet), true);
            break;
        case CF_GET_TYPE_EXT_OIDS:
            EXPECT_EQ(CompareOidsResult(typeValue, outParamSet), true);
            break;
        case CF_GET_TYPE_EXT_ENTRY:
            EXPECT_EQ(CompareEntryResult(typeValue, outParamSet), true);
            break;
        default:
            break;
    }
    CfFreeParamSet(&outParamSet);
}

static void ExtensionCheckTest(int32_t type, int32_t typeValue, const CfParam *params, uint32_t cnt)
{
    CfParamSet *outParamSet = nullptr;
    int32_t ret = CommonTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0], params, cnt, &outParamSet);
    EXPECT_EQ(ret, CF_SUCCESS);

#ifdef TEST_PRINT_DATA
    (void)GetOutValue(outParamSet);
#endif

    switch (type) {
        case CF_CHECK_TYPE_EXT_CA:
            EXPECT_EQ(CompareCheckResult(outParamSet), true);
            break;
        default:
            break;
    }
    CfFreeParamSet(&outParamSet);
}

/**
 * @tc.name: CfExtensionTest001
 * @tc.desc: get encoded
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest001, TestSize.Level0)
{
    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ITEM },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_ITEM_ENCODED },
    };
    ExtensionTest(CF_GET_TYPE_EXT_ITEM, CF_ITEM_ENCODED, params, sizeof(params) / sizeof(CfParam));
}

/**
 * @tc.name: CfExtensionTest002
 * @tc.desc: get oids all
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest002, TestSize.Level0)
{
    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_OIDS },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_EXT_TYPE_ALL_OIDS },
    };
    ExtensionTest(CF_GET_TYPE_EXT_OIDS, CF_EXT_TYPE_ALL_OIDS, params, sizeof(params) / sizeof(CfParam));
}

/**
 * @tc.name: CfExtensionTest003
 * @tc.desc: get oids critical
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest003, TestSize.Level0)
{
    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_OIDS },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_EXT_TYPE_CRITICAL_OIDS },
    };
    ExtensionTest(CF_GET_TYPE_EXT_OIDS, CF_EXT_TYPE_CRITICAL_OIDS, params, sizeof(params) / sizeof(CfParam));
}

/**
 * @tc.name: CfExtensionTest004
 * @tc.desc: get oids uncritical
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest004, TestSize.Level0)
{
    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_OIDS },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_EXT_TYPE_UNCRITICAL_OIDS },
    };
    ExtensionTest(CF_GET_TYPE_EXT_OIDS, CF_EXT_TYPE_UNCRITICAL_OIDS, params, sizeof(params) / sizeof(CfParam));
}

/**
 * @tc.name: CfExtensionTest005
 * @tc.desc: get entry
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest005, TestSize.Level0)
{
    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };

    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ENTRY },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_EXT_ENTRY_TYPE_ENTRY },
        { .tag = CF_TAG_PARAM1_BUFFER, .blob = oid },
    };
    ExtensionTest(CF_GET_TYPE_EXT_ENTRY, CF_EXT_ENTRY_TYPE_ENTRY, params, sizeof(params) / sizeof(CfParam));
}

/**
 * @tc.name: CfExtensionTest006
 * @tc.desc: get entry's critical
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest006, TestSize.Level0)
{
    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };

    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ENTRY },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_EXT_ENTRY_TYPE_ENTRY_CRITICAL },
        { .tag = CF_TAG_PARAM1_BUFFER, .blob = oid },
    };
    ExtensionTest(CF_GET_TYPE_EXT_ENTRY, CF_EXT_ENTRY_TYPE_ENTRY_CRITICAL, params, sizeof(params) / sizeof(CfParam));
}

/**
 * @tc.name: CfExtensionTest007
 * @tc.desc: get entry's value
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest007, TestSize.Level0)
{
    char oidStr[] = "2.5.29.19";
    CfBlob oid = { strlen(oidStr), reinterpret_cast<uint8_t *>(oidStr) };

    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ENTRY },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_EXT_ENTRY_TYPE_ENTRY_VALUE },
        { .tag = CF_TAG_PARAM1_BUFFER, .blob = oid },
    };
    ExtensionTest(CF_GET_TYPE_EXT_ENTRY, CF_EXT_ENTRY_TYPE_ENTRY_VALUE, params, sizeof(params) / sizeof(CfParam));
}

/**
 * @tc.name: CfExtensionTest008
 * @tc.desc: check ca
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest008, TestSize.Level0)
{
    CfParam params[] = {
        { .tag = CF_TAG_CHECK_TYPE, .int32Param = CF_CHECK_TYPE_EXT_CA },
    };
    ExtensionCheckTest(CF_CHECK_TYPE_EXT_CA, 0, params, sizeof(params) / sizeof(CfParam));
}

/**
 * @tc.name: CfExtensionTest009
 * @tc.desc: create object
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest009, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0], &object);
    ASSERT_EQ(ret, CF_SUCCESS);

    object->destroy(&object);
}

/**
 * @tc.name: CfExtensionTest010
 * @tc.desc: CfCreate: in's data is invalid create failed
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest010, TestSize.Level0)
{
    CfObject *object = nullptr;
    uint8_t invalidData[] = { 0x30, 0x33, 0x44, 0x55, }; /* in's data is invalid create failed */
    CfEncodingBlob cert = { invalidData, sizeof(invalidData), CF_FORMAT_DER };
    int32_t ret = CfCreate(CF_OBJ_TYPE_EXTENSION, &cert, &object);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest012
 * @tc.desc: CfCreate:in's data is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest011, TestSize.Level0)
{
    CfObject *object = nullptr;
    uint8_t invalidData[] = { 0x30, 0x11, 0x22, 0x33, };
    CfEncodingBlob cert = { nullptr, sizeof(invalidData), CF_FORMAT_DER }; /* in's data is nullptr */
    int32_t ret = CfCreate(CF_OBJ_TYPE_EXTENSION, &cert, &object);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest013
 * @tc.desc: CfCreate:in's size is 0
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest012, TestSize.Level0)
{
    CfObject *object = nullptr;
    uint8_t invalidData[] = { 0x30, 0x01, 0x02, 0x03, };
    CfEncodingBlob cert = { invalidData, 0, CF_FORMAT_DER }; /* in's size is 0 */
    int32_t ret = CfCreate(CF_OBJ_TYPE_EXTENSION, &cert, &object);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest013
 * @tc.desc: CfCreate:in's encodingFormat invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest013, TestSize.Level0)
{
    CfObject *object = nullptr;
    CfEncodingBlob cert = { const_cast<uint8_t *>(g_extensionData03), sizeof(g_extensionData03), CF_FORMAT_PEM };
    int32_t ret = CfCreate(CF_OBJ_TYPE_EXTENSION, &cert, &object);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest014
 * @tc.desc: ->check: inParamSet not set CF_TAG_CHECK_TYPE
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest014, TestSize.Level0)
{
    CfParam params[] = { /* not set CF_TAG_CHECK_TYPE */
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ITEM },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_CHECK);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest015
 * @tc.desc: ->check: inParamSet‘s CF_TAG_CHECK_TYPE is not CF_CHECK_TYPE_EXT_CA
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest015, TestSize.Level0)
{
    CfParam params[] = { /* CF_TAG_CHECK_TYPE is not CF_CHECK_TYPE_EXT_CA */
        { .tag = CF_TAG_CHECK_TYPE, .int32Param = 0xff },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_CHECK);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest016
 * @tc.desc: ->check: adapter return error  g_extDataNoKeyUsage
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest016, TestSize.Level0)
{
    CfParam params[] = {
        { .tag = CF_TAG_CHECK_TYPE, .int32Param = CF_CHECK_TYPE_EXT_CA },
    };

    /* ext data not has keyusage */
    CfEncodingBlob blob = {
        const_cast<uint8_t *>(g_extDataNoKeyUsage), sizeof(g_extDataNoKeyUsage), CF_FORMAT_DER
    };
    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &blob, params, sizeof(params) / sizeof(CfParam), OP_TYPE_CHECK);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest017
 * @tc.desc: ->get: inParamSet not set CF_TAG_GET_TYPE
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest017, TestSize.Level0)
{
    CfParam params[] = { /* not set CF_TAG_GET_TYPE */
        { .tag = CF_TAG_CHECK_TYPE, .int32Param = CF_CHECK_TYPE_EXT_CA },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest018
 * @tc.desc: ->get: inParamSet's CF_TAG_GET_TYPE not valid
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest018, TestSize.Level0)
{
    CfParam params[] = { /* CF_TAG_GET_TYPE not valid */
        { .tag = CF_TAG_GET_TYPE, .int32Param = 0xff },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest019
 * @tc.desc: ->get: inParamSet's type is CF_GET_TYPE_EXT_ITEM, not set CF_TAG_PARAM0_INT32
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest019, TestSize.Level0)
{
    CfParam params[] = { /* not set CF_TAG_PARAM0_INT32 */
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ITEM },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest020
 * @tc.desc: ->get: inParamSet's type is CF_GET_TYPE_EXT_ITEM, CF_TAG_PARAM0_INT32 is invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest020, TestSize.Level0)
{
    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ITEM },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = 0xff }, /* CF_TAG_PARAM0_INT32 is invalid */
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest021
 * @tc.desc: ->get: inParamSet's type is CF_GET_TYPE_EXT_OIDS, not set CF_TAG_PARAM0_INT32
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest021, TestSize.Level0)
{
    CfParam params[] = { /* not set CF_TAG_PARAM0_INT32 */
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_OIDS },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest022
 * @tc.desc: ->get: inParamSet's type is CF_GET_TYPE_EXT_OIDS, CF_TAG_PARAM0_INT32 is invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest022, TestSize.Level0)
{
    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_OIDS },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = 0xff }, /* CF_TAG_PARAM0_INT32 is invalid */
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest023
 * @tc.desc: ->get: inParamSet's type is CF_GET_TYPE_EXT_ENTRY, not set CF_TAG_PARAM0_INT32
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest023, TestSize.Level0)
{
    CfParam params[] = { /* not set CF_TAG_PARAM0_INT32 */
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ENTRY },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest024
 * @tc.desc: ->get: inParamSet's type is CF_GET_TYPE_EXT_ENTRY, not set CF_TAG_PARAM1_BUFFER
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest024, TestSize.Level0)
{
    CfParam params[] = { /* not set CF_TAG_PARAM1_BUFFER */
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ENTRY },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_EXT_ENTRY_TYPE_ENTRY_CRITICAL },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfExtensionTest025
 * @tc.desc: ->get: inParamSet's type is CF_GET_TYPE_EXT_ENTRY, CF_TAG_PARAM0_INT32 is invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest025, TestSize.Level0)
{
    uint8_t oidData[] = "2.5.29.19";
    CfBlob oidBlob = { sizeof(oidData), oidData };
    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ENTRY },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = 0xff }, /* CF_TAG_PARAM0_INT32 is invalid */
        { .tag = CF_TAG_PARAM1_BUFFER, .blob = oidBlob },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_EXTENSION, &g_extensionBlob[0],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}
/**
 * @tc.name: CfExtensionTest026
 * @tc.desc: check unsupport critical
 * @tc.type: FUNC
 * @tc.require: AR000HS2SC /SR000HS2SB
 */
HWTEST_F(CfExtensionTest, CfExtensionTest026, TestSize.Level0)
{
    CfParam params[] = {
        { .tag = CF_TAG_CHECK_TYPE, .int32Param = CF_CHECK_TYPE_EXT_HAS_UN_SUPPORT },
    };
    ExtensionCheckTest(CF_CHECK_TYPE_EXT_HAS_UN_SUPPORT, 0, params, sizeof(params) / sizeof(CfParam));
}
}
