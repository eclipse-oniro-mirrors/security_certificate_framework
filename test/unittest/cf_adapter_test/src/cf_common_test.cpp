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

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "cf_type.h"
#include "utils.h"

using namespace testing::ext;
namespace {
constexpr uint32_t TEST_DEFAULT_SIZE = 10;
constexpr uint32_t TEST_DEFAULT_COUNT = 2;
class CfCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CfCommonTest::SetUpTestCase(void)
{
}

void CfCommonTest::TearDownTestCase(void)
{
}

void CfCommonTest::SetUp()
{
}

void CfCommonTest::TearDown()
{
}

/**
* @tc.name: CfBlobDataFree001
* @tc.desc: CfBlobDataFree normal case
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, CfBlobDataFree001, TestSize.Level0)
{
    CfBlobDataFree(nullptr);
    CfBlob blobNull = { 0, nullptr };
    CfBlobDataFree(&blobNull);
    CfBlob blob = { TEST_DEFAULT_SIZE, nullptr };
    blob.data = static_cast<uint8_t *>(CfMalloc(blob.size, 0));
    ASSERT_NE(blob.data, nullptr);
    CfBlobDataFree(&blob);
}

/**
* @tc.name: CfBlobDataClearAndFree001
* @tc.desc: CfBlobDataClearAndFree normal case
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, CfBlobDataClearAndFree001, TestSize.Level0)
{
    CfBlobDataClearAndFree(nullptr);
    CfBlob blobNull = { 0, nullptr };
    CfBlobDataClearAndFree(&blobNull);
    CfBlob blob = { TEST_DEFAULT_SIZE, nullptr };
    blob.data = static_cast<uint8_t *>(CfMalloc(blob.size, 0));
    ASSERT_NE(blob.data, nullptr);
    CfBlobDataClearAndFree(&blob);
}

/**
* @tc.name: CfEncodingBlobDataFree001
* @tc.desc: CfEncodingBlobDataFree normal case
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, CfEncodingBlobDataFree001, TestSize.Level0)
{
    CfEncodingBlobDataFree(nullptr);
    CfEncodingBlob blobNull = { nullptr, 0, CF_FORMAT_DER };
    CfEncodingBlobDataFree(&blobNull);
    CfEncodingBlob blob = { nullptr, TEST_DEFAULT_SIZE, CF_FORMAT_DER };
    blob.data = static_cast<uint8_t *>(CfMalloc(blob.len, 0));
    ASSERT_NE(blob.data, nullptr);
    CfEncodingBlobDataFree(&blob);
}

/**
* @tc.name: CfArrayDataClearAndFree01
* @tc.desc: CfArrayDataClearAndFree normal case
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, CfArrayDataClearAndFree001, TestSize.Level0)
{
    CfArrayDataClearAndFree(nullptr);
    CfArray array = { nullptr, CF_FORMAT_DER, TEST_DEFAULT_COUNT };
    array.data = static_cast<CfBlob *>(CfMalloc(array.count * sizeof(CfBlob), 0));
    ASSERT_NE(array.data, nullptr);

    for (uint32_t i = 0; i < array.count; ++i) {
        array.data[i].size = TEST_DEFAULT_SIZE;
        array.data[i].data = static_cast<uint8_t *>(CfMalloc(array.data[i].size, 0));
        ASSERT_NE(array.data[i].data, nullptr);
    }

    CfArrayDataClearAndFree(&array);
}

/**
* @tc.name: FreeCfBlobArray002
* @tc.desc: FreeCfBlobArray normal case
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, FreeCfBlobArray002, TestSize.Level0)
{
    FreeCfBlobArray(nullptr, 0);
    CfBlob *array = static_cast<CfBlob *>(CfMalloc(TEST_DEFAULT_COUNT * sizeof(CfBlob), 0));
    ASSERT_NE(array, nullptr);

    FreeCfBlobArray(array, TEST_DEFAULT_COUNT);
}

/**
* @tc.name: FreeCfBlobArray003
* @tc.desc: FreeCfBlobArray normal case 2
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, FreeCfBlobArray003, TestSize.Level0)
{
    CF_LOG_W("this is test for log Warn");
    CF_LOG_I("this is test for log Info");
    CF_LOG_E("this is test for log Error");
    CF_LOG_D("this is test for log Debug");
    CF_LOG_W("MoreThan512Bytes................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "................................................................"
        "..................................................................");
    CfBlob *array = static_cast<CfBlob *>(CfMalloc(TEST_DEFAULT_COUNT * sizeof(CfBlob), 0));
    ASSERT_NE(array, nullptr);

    for (uint32_t i = 0; i < TEST_DEFAULT_COUNT; ++i) {
        array[i].size = TEST_DEFAULT_SIZE;
        array[i].data = static_cast<uint8_t *>(CfMalloc(array[i].size, 0));
        ASSERT_NE(array[i].data, nullptr);
    }

    FreeCfBlobArray(array, TEST_DEFAULT_COUNT);
}

/**
* @tc.name: CfMemTest001
* @tc.desc: malloc and free normal
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, CfMemTest001, TestSize.Level0)
{
    CfFree(nullptr);
    uint8_t *buf = static_cast<uint8_t *>(CfMalloc(TEST_DEFAULT_SIZE, 0));
    ASSERT_NE(buf, nullptr);
    CfFree(buf);
}

/**
* @tc.name: CfMemTest002
* @tc.desc: malloc 0
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, CfMemTest002, TestSize.Level0)
{
    uint8_t *buf = static_cast<uint8_t *>(CfMalloc(0, 0));
    ASSERT_EQ(buf, nullptr);
}

/**
* @tc.name: CfMemTest003
* @tc.desc: malloc more than MAX_MEMORY_SIZE
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, CfMemTest003, TestSize.Level0)
{
    uint8_t *buf = static_cast<uint8_t *>(CfMalloc(MAX_MEMORY_SIZE + 1, 0));
    ASSERT_EQ(buf, nullptr);
}

/**
* @tc.name: IsStrValid001
* @tc.desc: str is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsStrValid001, TestSize.Level0)
{
    bool checkRes = CfIsStrValid(nullptr, 0);
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsStrValid002
* @tc.desc: len invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsStrValid002, TestSize.Level0)
{
    char str[] = "this is test for beyond max length.";
    bool checkRes = CfIsStrValid(str, TEST_DEFAULT_SIZE);
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsStrValid003
* @tc.desc: normal case
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsStrValid003, TestSize.Level0)
{
    char str[] = "123456789";
    bool checkRes = CfIsStrValid(str, TEST_DEFAULT_SIZE);
    EXPECT_EQ(checkRes, true);
}

/**
* @tc.name: IsBlobValid001
* @tc.desc: normal case
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsBlobValid001, TestSize.Level0)
{
    uint8_t blobData[] = "normal case";
    CfBlob blob = { sizeof(blobData), blobData };
    bool checkRes = CfIsBlobValid(&blob);
    EXPECT_EQ(checkRes, true);
}

/**
* @tc.name: IsBlobValid002
* @tc.desc: blob is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsBlobValid002, TestSize.Level0)
{
    bool checkRes = CfIsBlobValid(nullptr);
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsBlobValid003
* @tc.desc: blob data is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsBlobValid003, TestSize.Level0)
{
    CfBlob blob = { TEST_DEFAULT_SIZE, nullptr };
    bool checkRes = CfIsBlobValid(&blob);
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsBlobValid004
* @tc.desc: blob size is 0
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsBlobValid004, TestSize.Level0)
{
    uint8_t blobData[] = "invalid blob size is 0";
    CfBlob blob = { 0, blobData };
    bool checkRes = CfIsBlobValid(&blob);
    EXPECT_EQ(checkRes, false);
}

static const char *GetClass(void)
{
    return "TEST_FOR_GET_CLASS";
}

static const char *GetClassNull(void)
{
    return nullptr;
}

/**
* @tc.name: IsClassMatch001
* @tc.desc: obj is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsClassMatch001, TestSize.Level0)
{
    bool checkRes = CfIsClassMatch(nullptr, "TEST_FOR_GET_CLASS");
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsClassMatch002
* @tc.desc: obj->getClass() is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsClassMatch002, TestSize.Level0)
{
    CfObjectBase obj = { GetClassNull, nullptr };
    bool checkRes = CfIsClassMatch(&obj, "TEST_FOR_GET_CLASS");
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsClassMatch003
* @tc.desc: class is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsClassMatch003, TestSize.Level0)
{
    CfObjectBase obj = { GetClass, nullptr };
    bool checkRes = CfIsClassMatch(&obj, nullptr);
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsClassMatch004
* @tc.desc: normal case
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsClassMatch004, TestSize.Level0)
{
    CfObjectBase obj = { GetClass, nullptr };
    bool checkRes = CfIsClassMatch(&obj, "TEST_FOR_GET_CLASS");
    EXPECT_EQ(checkRes, true);
}

/**
* @tc.name: IsClassMatch005
* @tc.desc: class not equal
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsClassMatch005, TestSize.Level0)
{
    CfObjectBase obj = { GetClass, nullptr };
    bool checkRes = CfIsClassMatch(&obj, "TEST_FOR_GET_CLASS123");
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsPubKeyClassMatch001
* @tc.desc: normal case
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsPubKeyClassMatch001, TestSize.Level0)
{
    HcfObjectBase obj = { GetClass, nullptr };
    bool checkRes = CfIsPubKeyClassMatch(&obj, "TEST_FOR_GET_CLASS");
    EXPECT_EQ(checkRes, true);
}

/**
* @tc.name: IsPubKeyClassMatch002
* @tc.desc: class not equal
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsPubKeyClassMatch002, TestSize.Level0)
{
    HcfObjectBase obj = { GetClass, nullptr };
    bool checkRes = CfIsPubKeyClassMatch(&obj, "TEST_FOR_GET_CLASS000");
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsPubKeyClassMatch003
* @tc.desc: obj is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsPubKeyClassMatch003, TestSize.Level0)
{
    bool checkRes = CfIsPubKeyClassMatch(nullptr, "TEST_FOR_GET_CLASS");
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsPubKeyClassMatch004
* @tc.desc: obj->getClass() is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsPubKeyClassMatch004, TestSize.Level0)
{
    HcfObjectBase obj = { GetClassNull, nullptr };
    bool checkRes = CfIsPubKeyClassMatch(&obj, "TEST_FOR_GET_CLASS");
    EXPECT_EQ(checkRes, false);
}

/**
* @tc.name: IsPubKeyClassMatch005
* @tc.desc: class is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfCommonTest, IsPubKeyClassMatch005, TestSize.Level0)
{
    HcfObjectBase obj = { GetClass, nullptr };
    bool checkRes = CfIsPubKeyClassMatch(&obj, nullptr);
    EXPECT_EQ(checkRes, false);
}
} // end of namespace
