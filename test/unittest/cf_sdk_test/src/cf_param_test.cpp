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

#include "cf_param.h"
#include "cf_result.h"
#include "cf_type.h"

using namespace testing::ext;
namespace {
constexpr int32_t CF_TAG_PARAM0_BOOL = 0x1;
class CfParamTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CfParamTest::SetUpTestCase(void)
{
}

void CfParamTest::TearDownTestCase(void)
{
}

void CfParamTest::SetUp()
{
}

void CfParamTest::TearDown()
{
}

/**
* @tc.name: CfInitParamSet001
* @tc.desc: test CfInitParamSet nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfInitParamSet001, TestSize.Level0)
{
    int32_t ret = CfInitParamSet(nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
* @tc.name: CfAddParams001
* @tc.desc: test CfAddParams paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfAddParams001, TestSize.Level0)
{
    CfParam param[] = {
        { .tag = CF_TAG_PARAM0_BOOL, .boolParam = false },
    };
    int32_t ret = CfAddParams(nullptr, param, sizeof(param) / sizeof(CfParam));
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
* @tc.name: CfAddParams002
* @tc.desc: test CfAddParams param is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfAddParams002, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);

    ret = CfAddParams(paramSet, nullptr, 0);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfAddParams003
* @tc.desc: test CfAddParams paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfAddParams003, TestSize.Level0)
{
    CfParamSet paramSet = { CF_PARAM_SET_MAX_SIZE + 1, 0 };
    CfParam param[] = {
        { .tag = CF_TAG_PARAM0_BOOL, .boolParam = false },
    };
    int32_t ret = CfAddParams(&paramSet, param, sizeof(param) / sizeof(CfParam));
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
* @tc.name: CfAddParams004
* @tc.desc: test CfAddParams param cnt is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfAddParams004, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfParam param[] = {
        { .tag = CF_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CfAddParams(paramSet, param, CF_DEFAULT_PARAM_CNT + 1);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfAddParams005
* @tc.desc: test CfAddParams paramSet cnt is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfAddParams005, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);
    paramSet->paramsCnt = CF_DEFAULT_PARAM_CNT;

    CfParam param[] = {
        { .tag = CF_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CfAddParams(paramSet, param, sizeof(param) / sizeof(CfParam));
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfAddParams006
* @tc.desc: test CfAddParams param tag blob.data is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfAddParams006, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfBlob tempBlob = { 1, nullptr };
    CfParam param[] = {
        { .tag = CF_TAG_PARAM0_BUFFER, .blob = tempBlob },
    };
    ret = CfAddParams(paramSet, param, sizeof(param) / sizeof(CfParam));
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfAddParams007
* @tc.desc: test CfAddParams param tag blob.size is 0
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfAddParams007, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);

    uint8_t tempBuf[] = "this is for test 007";
    CfBlob tempBlob = { 0, tempBuf };
    CfParam param[] = {
        { .tag = CF_TAG_PARAM0_BUFFER, .blob = tempBlob },
    };
    ret = CfAddParams(paramSet, param, sizeof(param) / sizeof(CfParam));
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfAddParams008
* @tc.desc: test CfAddParams param size after add invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfAddParams008, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);

    paramSet->paramSetSize = CF_PARAM_SET_MAX_SIZE - 1; /* after add sizeof(tempBuf) invalid */

    uint8_t tempBuf[] = "this is for test 007";
    CfBlob tempBlob = { sizeof(tempBuf), tempBuf };
    CfParam param[] = {
        { .tag = CF_TAG_PARAM0_BUFFER, .blob = tempBlob },
        { .tag = CF_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CfAddParams(paramSet, param, sizeof(param) / sizeof(CfParam));
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfAddParams009
* @tc.desc: test CfAddParams param tag blob.size is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfAddParams009, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);

    uint8_t tempBuf[] = "this is for test";
    CfBlob tempBlob = { UINT32_MAX, tempBuf };
    CfParam param[] = {
        { .tag = CF_TAG_PARAM0_BUFFER, .blob = tempBlob },
    };
    ret = CfAddParams(paramSet, param, sizeof(param) / sizeof(CfParam));
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfGetParam001
* @tc.desc: test CfGetParam paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfGetParam001, TestSize.Level0)
{
    CfParam *param = nullptr;
    int32_t ret = CfGetParam(nullptr, CF_TAG_PARAM0_BUFFER, &param);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
* @tc.name: CfGetParam002
* @tc.desc: test CfGetParam out param is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfGetParam002, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);

    ret = CfGetParam(paramSet, CF_TAG_PARAM0_BUFFER, nullptr);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfGetParam003
* @tc.desc: test CfGetParam paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfGetParam003, TestSize.Level0)
{
    CfParamSet paramSet = {CF_PARAM_SET_MAX_SIZE + 1, 1 };
    CfParam *param = nullptr;
    int32_t ret = CfGetParam(&paramSet, CF_TAG_PARAM0_BUFFER, &param);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
* @tc.name: CfGetParam004
* @tc.desc: test CfGetParam paramSet size is invalid (smaller than struct size)
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfGetParam004, TestSize.Level0)
{
    CfParamSet paramSet = { sizeof(CfParamSet) - 1, 1 };
    CfParam *param = nullptr;
    int32_t ret = CfGetParam(&paramSet, CF_TAG_PARAM0_BUFFER, &param);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
* @tc.name: CfGetParam005
* @tc.desc: test CfGetParam paramSet cnt is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfGetParam005, TestSize.Level0)
{
    CfParamSet paramSet = { sizeof(CfParamSet), 1 };
    CfParam *param = nullptr;
    int32_t ret = CfGetParam(&paramSet, CF_TAG_PARAM0_BUFFER, &param);
    EXPECT_NE(ret, CF_SUCCESS);
}

static void ConstrutParamSet(CfParamSet **paramSet)
{
    int32_t ret = CfInitParamSet(paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfParam param[] = {
        { .tag = CF_TAG_PARAM0_BOOL, .boolParam = false },
    };
    ret = CfAddParams(*paramSet, param, sizeof(param) / sizeof(CfParam));
    EXPECT_EQ(ret, CF_SUCCESS);

    ret = CfBuildParamSet(paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);
}

/**
* @tc.name: CfGetParam006
* @tc.desc: test CfGetParam normal testcase
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfGetParam006, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    ConstrutParamSet(&paramSet);

    CfParam *param = nullptr;
    int32_t ret = CfGetParam(paramSet, CF_TAG_PARAM0_BOOL, &param);
    EXPECT_EQ(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfGetParam007
* @tc.desc: test CfGetParam param not exist
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfGetParam007, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    ConstrutParamSet(&paramSet);

    CfParam *param = nullptr;
    int32_t ret = CfGetParam(paramSet, CF_TAG_PARAM0_BUFFER, &param);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfFreeParamSet001
* @tc.desc: test CfFreeParamSet paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfFreeParamSet001, TestSize.Level0)
{
    CfFreeParamSet(nullptr);
}

/**
* @tc.name: CfBuildParamSet001
* @tc.desc: test CfBuildParamSet paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfBuildParamSet001, TestSize.Level0)
{
    int32_t ret = CfBuildParamSet(nullptr);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
* @tc.name: CfBuildParamSet002
* @tc.desc: test CfBuildParamSet *paramSet is nullptr
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfBuildParamSet002, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfBuildParamSet(&paramSet);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
* @tc.name: CfBuildParamSet003
* @tc.desc: test CfBuildParamSet paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfBuildParamSet003, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);
    if (ret != CF_SUCCESS) {
        return;
    }
    paramSet->paramSetSize = sizeof(CfParamSet) - 1;

    ret = CfBuildParamSet(&paramSet);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfBuildParamSet004
* @tc.desc: test CfBuildParamSet param tag blob size is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfBuildParamSet004, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);
    if (ret != CF_SUCCESS) {
        return;
    }

    uint8_t tempBuf[] = "this is for test020";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(CfParam);
    paramSet->params[0].tag = CF_TAG_PARAM1_BUFFER;
    paramSet->params[0].blob.size = UINT32_MAX;
    paramSet->params[0].blob.data = tempBuf;

    ret = CfBuildParamSet(&paramSet);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfBuildParamSet005
* @tc.desc: test CfBuildParamSet param tag blob data is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfBuildParamSet005, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);
    if (ret != CF_SUCCESS) {
        return;
    }

    uint8_t tempBuf[] = "this is for test021";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(CfParam) + sizeof(tempBuf);
    paramSet->params[0].tag = CF_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = nullptr;

    ret = CfBuildParamSet(&paramSet);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}

/**
* @tc.name: CfBuildParamSet006
* @tc.desc: test CfBuildParamSet paramSet size is invalid
* @tc.type: FUNC
* @tc.require: AR000HS2RB /SR000HS2Q1
*/
HWTEST_F(CfParamTest, CfBuildParamSet006, TestSize.Level0)
{
    CfParamSet *paramSet = nullptr;
    int32_t ret = CfInitParamSet(&paramSet);
    EXPECT_EQ(ret, CF_SUCCESS);
    if (ret != CF_SUCCESS) {
        return;
    }

    uint8_t tempBuf[] = "this is for test022";
    paramSet->paramsCnt = 1;
    paramSet->paramSetSize += sizeof(CfParam) + sizeof(tempBuf) + 1; /* invalid size */
    paramSet->params[0].tag = CF_TAG_PARAM0_BUFFER;
    paramSet->params[0].blob.size = sizeof(tempBuf);
    paramSet->params[0].blob.data = tempBuf;

    ret = CfBuildParamSet(&paramSet);
    EXPECT_NE(ret, CF_SUCCESS);

    CfFreeParamSet(&paramSet);
}
} // end of namespace
