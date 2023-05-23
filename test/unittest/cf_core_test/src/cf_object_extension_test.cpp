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

#include "securec.h"

#include "cf_api.h"
#include "cf_param.h"
#include "cf_type.h"
#include "cf_result.h"

#include "cf_test_data.h"

#include "cf_object_extension.h"
#include "cf_extension_adapter_ability_define.h"

using namespace testing::ext;
using namespace CertframeworkTestData;

namespace {
class CfObjectExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CfObjectExtensionTest::SetUpTestCase(void)
{
}

void CfObjectExtensionTest::TearDownTestCase(void)
{
}

void CfObjectExtensionTest::SetUp()
{
}

void CfObjectExtensionTest::TearDown()
{
}

const static CfEncodingBlob g_extension = {
    const_cast<uint8_t *>(g_extensionData03), sizeof(g_extensionData03), CF_FORMAT_DER
};

struct CfExtensionObjStruct_ {
    CfBase base;
    CfExtensionAdapterAbilityFunc func;
    CfBase *adapterRes;
};

using CfExtensionObjStruct = CfExtensionObjStruct_;

/**
 * @tc.name: CfObjectExtensionTest001
 * @tc.desc: CfExtensionCreate: in is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest001, TestSize.Level0)
{
    CfBase *obj = nullptr;
    int32_t ret = CfExtensionCreate(nullptr, &obj); /* in is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectExtensionTest002
 * @tc.desc: CfExtensionCreate: obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest002, TestSize.Level0)
{
    int32_t ret = CfExtensionCreate(&g_extension, nullptr); /* obj is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectExtensionTest003
 * @tc.desc: CfExtensionDestroy: obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest003, TestSize.Level0)
{
    CfExtensionDestroy(nullptr); /* obj is nullptr coverage */
}

/**
 * @tc.name: CfObjectExtensionTest004
 * @tc.desc: CfExtensionDestroy: *obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest004, TestSize.Level0)
{
    CfBase *obj = nullptr;
    CfExtensionDestroy(&obj); /* *obj is nullptr coverage */
}

/**
 * @tc.name: CfObjectExtensionTest005
 * @tc.desc: CfExtensionDestroy: baseType magicid invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest005, TestSize.Level0)
{
    CfExtensionObjStruct extObj;
    (void)memset_s(&extObj, sizeof(extObj), 0, sizeof(extObj));

    extObj.base.type = 0xff; /* baseType magicid invalid */
    CfBase *base = &extObj.base;

    CfExtensionDestroy(&base);
}

/**
 * @tc.name: CfObjectExtensionTest006
 * @tc.desc: CfExtensionCheck: obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest006, TestSize.Level0)
{
    CfParamSet in;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    CfParamSet *out = nullptr;
    int32_t ret = CfExtensionCheck(nullptr, &in, &out); /* obj is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectExtensionTest007
 * @tc.desc: CfExtensionCheck: in is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest007, TestSize.Level0)
{
    CfBase base;
    (void)memset_s(&base, sizeof(base), 0, sizeof(base));
    CfParamSet *out = nullptr;
    int32_t ret = CfExtensionCheck(&base, nullptr, &out); /* in is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectExtensionTest008
 * @tc.desc: CfExtensionCheck: out is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest008, TestSize.Level0)
{
    CfParamSet in;
    CfBase base;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    (void)memset_s(&base, sizeof(base), 0, sizeof(base));
    int32_t ret = CfExtensionCheck(&base, &in, nullptr); /* out is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectExtensionTest009
 * @tc.desc: CfExtensionCheck: baseType magicid invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest009, TestSize.Level0)
{
    CfParamSet in;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    CfParamSet *out = nullptr;

    CfExtensionObjStruct extObj;
    (void)memset_s(&extObj, sizeof(extObj), 0, sizeof(extObj));
    extObj.base.type = 0xff; /* baseType magicid invalid */

    int32_t ret = CfExtensionCheck(&extObj.base, &in, &out);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectExtensionTest010
 * @tc.desc: CfExtensionGet: obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest010, TestSize.Level0)
{
    CfParamSet in;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    CfParamSet *out = nullptr;
    int32_t ret = CfExtensionGet(nullptr, &in, &out); /* obj is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectExtensionTest011
 * @tc.desc: CfExtensionGet: in is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest011, TestSize.Level0)
{
    CfBase base;
    (void)memset_s(&base, sizeof(base), 0, sizeof(base));
    CfParamSet *out = nullptr;
    int32_t ret = CfExtensionGet(&base, nullptr, &out); /* in is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectExtensionTest012
 * @tc.desc: CfExtensionGet: out is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest012, TestSize.Level0)
{
    CfParamSet in;
    CfBase base;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    (void)memset_s(&base, sizeof(base), 0, sizeof(base));
    int32_t ret = CfExtensionGet(&base, &in, nullptr); /* out is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectExtensionTest013
 * @tc.desc: CfExtensionGet: baseType magicid invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectExtensionTest, CfObjectExtensionTest013, TestSize.Level0)
{
    CfParamSet in;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    CfParamSet *out = nullptr;

    CfExtensionObjStruct extObj;
    (void)memset_s(&extObj, sizeof(extObj), 0, sizeof(extObj));
    extObj.base.type = 0xff; /* baseType magicid invalid */

    int32_t ret = CfExtensionGet(&extObj.base, &in, &out);
    EXPECT_NE(ret, CF_SUCCESS);
}
}
