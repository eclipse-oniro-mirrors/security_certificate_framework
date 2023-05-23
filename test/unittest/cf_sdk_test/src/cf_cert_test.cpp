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

#include "cf_api.h"
#include "cf_param.h"
#include "cf_result.h"
#include "cf_type.h"

#include "cf_test_common.h"
#include "cf_test_data.h"
#include "cf_test_sdk_common.h"

using namespace testing::ext;
using namespace CertframeworkTestData;
using namespace CertframeworkTest;
using namespace CertframeworkSdkTest;

namespace {
constexpr int32_t DER_FORMAT_INDEX = 0;
constexpr int32_t PEM_FORMAT_INDEX = 1;
class CfCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CfCertTest::SetUpTestCase(void)
{
}

void CfCertTest::TearDownTestCase(void)
{
}

void CfCertTest::SetUp()
{
}

void CfCertTest::TearDown()
{
}

const static CfEncodingBlob g_cert[] = {
    { const_cast<uint8_t *>(g_certData01), sizeof(g_certData01), CF_FORMAT_DER },
    { reinterpret_cast<uint8_t *>(g_certData02), sizeof(g_certData02), CF_FORMAT_PEM }
};

const static CfBlob g_certTbs = { sizeof(g_certData01TBS), const_cast<uint8_t *>(g_certData01TBS) };
const static CfBlob g_certPemTbs = { sizeof(g_certData02TBS), const_cast<uint8_t *>(g_certData02TBS) };
const static CfBlob g_certIssueUid = { sizeof(g_certData01IssuerUID), const_cast<uint8_t *>(g_certData01IssuerUID) };
const static CfBlob g_certSubUid = { sizeof(g_certData01SubjectUID), const_cast<uint8_t *>(g_certData01SubjectUID) };
const static CfBlob g_certExt = { sizeof(g_extensionData01), const_cast<uint8_t *>(g_extensionData01) };
const static CfBlob g_certPubKey = { sizeof(g_certData01PubKey), const_cast<uint8_t *>(g_certData01PubKey) };

static bool CompareResult(CfItemId id, const CfParamSet *out, enum CfEncodingFormat format)
{
    CfParam *resultTypeParam = NULL;
    int32_t ret = CfGetParam(out, CF_TAG_RESULT_TYPE, &resultTypeParam);
    if (ret != CF_SUCCESS) {
        printf("get CF_TAG_RESULT_TYPE failed.\n");
        return false;
    }

    if (resultTypeParam->int32Param != CF_TAG_TYPE_BYTES) {
        printf("result type is not CF_TAG_TYPE_BYTES.\n");
        return false;
    }

    CfParam *resultParam = NULL;
    ret = CfGetParam(out, CF_TAG_RESULT_BYTES, &resultParam);
    if (ret != CF_SUCCESS) {
        printf("get CF_TAG_RESULT_BYTES from out failed.\n");
        return false;
    }

    switch (id) {
        case CF_ITEM_TBS:
            if (format == CF_FORMAT_DER) {
                return CompareBlob(&resultParam->blob, &g_certTbs);
            }
            return CompareBlob(&resultParam->blob, &g_certPemTbs);
        case CF_ITEM_ISSUER_UNIQUE_ID:
            return CompareBlob(&resultParam->blob, &g_certIssueUid);
        case CF_ITEM_SUBJECT_UNIQUE_ID:
            return CompareBlob(&resultParam->blob, &g_certSubUid);
        case CF_ITEM_EXTENSIONS:
            return CompareBlob(&resultParam->blob, &g_certExt);
        case CF_ITEM_PUBLIC_KEY:
            return CompareBlob(&resultParam->blob, &g_certPubKey);
        default:
            return false;
    }
}

static void CertTest(CfItemId id, const CfEncodingBlob *in)
{
    CfParamSet *outParamSet = nullptr;
    CfParam params[] = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_CERT_ITEM },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = id },
    };
    int32_t ret = CommonTest(CF_OBJ_TYPE_CERT, in, params, sizeof(params) / sizeof(CfParam), &outParamSet);
    EXPECT_EQ(ret, CF_SUCCESS);
#ifdef TEST_PRINT_DATA
    (void)GetOutValue(outParamSet);
#endif
    EXPECT_EQ(CompareResult(id, outParamSet, in->encodingFormat), true);
    CfFreeParamSet(&outParamSet);
}

/**
 * @tc.name: CfCertTest001
 * @tc.desc: get tbs
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest001, TestSize.Level0)
{
    CertTest(CF_ITEM_TBS, &g_cert[DER_FORMAT_INDEX]);
}

/**
 * @tc.name: CfCertTest002
 * @tc.desc: get issuer unique id
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest002, TestSize.Level0)
{
    CertTest(CF_ITEM_ISSUER_UNIQUE_ID, &g_cert[DER_FORMAT_INDEX]);
}

/**
 * @tc.name: CfCertTest003
 * @tc.desc: get subject unique id
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest003, TestSize.Level0)
{
    CertTest(CF_ITEM_SUBJECT_UNIQUE_ID, &g_cert[DER_FORMAT_INDEX]);
}

/**
 * @tc.name: CfCertTest004
 * @tc.desc: get public key in der format
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest004, TestSize.Level0)
{
    CertTest(CF_ITEM_PUBLIC_KEY, &g_cert[DER_FORMAT_INDEX]);
}

/**
 * @tc.name: CfCertTest005
 * @tc.desc: get extension
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest005, TestSize.Level0)
{
    CertTest(CF_ITEM_EXTENSIONS, &g_cert[DER_FORMAT_INDEX]);
}

/**
 * @tc.name: CfCertTest006
 * @tc.desc: check func
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest006, TestSize.Level0)
{
    CfParamSet *outParamSet = nullptr;
    CfParam params[] = {
        { .tag = CF_TAG_CHECK_TYPE, .int32Param = 0 }, /* reserve test */
    };
    CommonTest(CF_OBJ_TYPE_CERT, &g_cert[0], params, sizeof(params) / sizeof(CfParam), &outParamSet);
    CfFreeParamSet(&outParamSet);
}

/**
 * @tc.name: CfCertTest007
 * @tc.desc: create object
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest007, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[0], &object);
    ASSERT_EQ(ret, CF_SUCCESS);

    object->destroy(&object);
}

/**
 * @tc.name: CfCertTest008
 * @tc.desc: pem format, get tbs
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest008, TestSize.Level0)
{
    CertTest(CF_ITEM_TBS, &g_cert[PEM_FORMAT_INDEX]);
}

/**
 * @tc.name: CfCertTest009
 * @tc.desc: CfCreate: in is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest009, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, nullptr, &object); /* in is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest010
 * @tc.desc: CfCreate: object is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest010, TestSize.Level0)
{
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX], nullptr); /* object is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest011
 * @tc.desc: CfCreate:objType is invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest011, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t cfObjType = 0xff; /* objType is invalid */
    int32_t ret = CfCreate(static_cast<CfObjectType>(cfObjType), &g_cert[DER_FORMAT_INDEX], &object);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest012
 * @tc.desc: CfCreate:in's data is invalid create failed
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest012, TestSize.Level0)
{
    CfObject *object = nullptr;
    uint8_t invalidData[] = { 0x30, 0x33, 0x44, 0x55, }; /* in's data is invalid create failed */
    CfEncodingBlob cert = { invalidData, sizeof(invalidData), CF_FORMAT_DER };
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &cert, &object);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest013
 * @tc.desc: CfCreate:in's data is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest013, TestSize.Level0)
{
    CfObject *object = nullptr;
    uint8_t invalidData[] = { 0x30, 0x11, 0x22, 0x33, };
    CfEncodingBlob cert = { nullptr, sizeof(invalidData), CF_FORMAT_DER }; /* in's data is nullptr */
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &cert, &object);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest014
 * @tc.desc: CfCreate:in's size is 0
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest014, TestSize.Level0)
{
    CfObject *object = nullptr;
    uint8_t invalidData[] = { 0x30, 0x01, 0x02, 0x03, };
    CfEncodingBlob cert = { invalidData, 0, CF_FORMAT_DER }; /* in's size is 0 */
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &cert, &object);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest015
 * @tc.desc: CfCreate:in's encodingFormat invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest015, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t format = 0xff;
    CfEncodingBlob cert = { reinterpret_cast<uint8_t *>(g_certData02), sizeof(g_certData02),
        static_cast<enum CfEncodingFormat>(format) };
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &cert, &object);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest016
 * @tc.desc: ->destroy: object is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest016, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX], &object);
    ASSERT_EQ(ret, CF_SUCCESS);

    object->destroy(nullptr); /* destroy: object is nullptr coverage */
    object->destroy(&object);
}

/**
 * @tc.name: CfCertTest017
 * @tc.desc: ->destroy: *object is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest017, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX], &object);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfObject *object1 = nullptr;
    object->destroy(&object1); /* destroy: *object is nullptr coverage */
    object->destroy(&object);
}

/**
 * @tc.name: CfCertTest018
 * @tc.desc: ->get: object is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest018, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX], &object);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfParamSet *inParamSet = nullptr;
    EXPECT_EQ(CfInitParamSet(&inParamSet), CF_SUCCESS);

    CfParamSet *outParamSet = nullptr;
    ret = object->get(nullptr, inParamSet, &outParamSet); /* object is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);

    object->destroy(&object);
    CfFreeParamSet(&inParamSet);
}

/**
 * @tc.name: CfCertTest019
 * @tc.desc: ->get: in is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest019, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX], &object);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfParamSet *outParamSet = nullptr;
    ret = object->get(object, nullptr, &outParamSet); /* inParamSet is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);

    object->destroy(&object);
}

/**
 * @tc.name: CfCertTest020
 * @tc.desc: ->get: out is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest020, TestSize.Level0)
{
    CfObject *object = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX], &object);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfParamSet *inParamSet = nullptr;
    EXPECT_EQ(CfInitParamSet(&inParamSet), CF_SUCCESS);

    ret = object->get(object, inParamSet, nullptr); /* outParamSet is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);

    object->destroy(&object);
    CfFreeParamSet(&inParamSet);
}

/**
 * @tc.name: CfCertTest021
 * @tc.desc: ->check: object is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest021, TestSize.Level0)
{
    CfObject *object021 = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX], &object021);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfParamSet *inParamSet = nullptr;
    EXPECT_EQ(CfInitParamSet(&inParamSet), CF_SUCCESS);

    CfParamSet *outParamSet = nullptr;
    ret = object021->check(nullptr, inParamSet, &outParamSet); /* check object is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);

    object021->destroy(&object021);
    CfFreeParamSet(&inParamSet);
}

/**
 * @tc.name: CfCertTest022
 * @tc.desc: ->check: in is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest022, TestSize.Level0)
{
    CfObject *object022 = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX], &object022);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfParamSet *outParamSet = nullptr;
    ret = object022->check(object022, nullptr, &outParamSet); /* check inParamSet is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);

    object022->destroy(&object022);
}

/**
 * @tc.name: CfCertTest023
 * @tc.desc: ->check: out is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest023, TestSize.Level0)
{
    CfObject *object023 = nullptr;
    int32_t ret = CfCreate(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX], &object023);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfParamSet *inParamSet = nullptr;
    EXPECT_EQ(CfInitParamSet(&inParamSet), CF_SUCCESS);

    ret = object023->check(object023, inParamSet, nullptr); /* check outParamSet is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);

    object023->destroy(&object023);
    CfFreeParamSet(&inParamSet);
}

/**
 * @tc.name: CfCertTest024
 * @tc.desc: ->get: inParamSet not set CF_TAG_GET_TYPE
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest024, TestSize.Level0)
{
    CfParam params[] = { /* inParamSet not set CF_TAG_GET_TYPE */
        { .tag = CF_TAG_CHECK_TYPE, .int32Param = CF_CHECK_TYPE_EXT_CA },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest025
 * @tc.desc: ->get: inParamSet's CF_TAG_GET_TYPE is not CF_GET_TYPE_CERT_ITEM
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest025, TestSize.Level0)
{
    CfParam params[] = { /* CF_TAG_GET_TYPE is not CF_GET_TYPE_CERT_ITEM */
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ITEM },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest026
 * @tc.desc: ->get: inParamSet not set CF_TAG_PARAM0_INT32
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest026, TestSize.Level0)
{
    CfParam params[] = { /* not set CF_TAG_PARAM0_INT32 */
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_CERT_ITEM },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfCertTest027
 * @tc.desc: ->get: inParamSet's CF_TAG_PARAM0_INT32 is not valid
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfCertTest, CfCertTest027, TestSize.Level0)
{
    CfParam params[] = { /* CF_TAG_PARAM0_INT32 is not valid */
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_CERT_ITEM },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_ITEM_INVALID },
    };

    int32_t ret = AbnormalTest(CF_OBJ_TYPE_CERT, &g_cert[DER_FORMAT_INDEX],
        params, sizeof(params) / sizeof(CfParam), OP_TYPE_GET);
    EXPECT_EQ(ret, CF_SUCCESS);
}
}

