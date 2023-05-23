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

#include "cf_cert_adapter_ability_define.h"
#include "cf_object_cert.h"

using namespace testing::ext;
using namespace CertframeworkTestData;

namespace {
class CfObjectCertTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CfObjectCertTest::SetUpTestCase(void)
{
}

void CfObjectCertTest::TearDownTestCase(void)
{
}

void CfObjectCertTest::SetUp()
{
}

void CfObjectCertTest::TearDown()
{
}

const static CfEncodingBlob g_cert = { const_cast<uint8_t *>(g_certData01), sizeof(g_certData01), CF_FORMAT_DER };

struct CfCertObjStruct_ {
    CfBase base;
    CfCertAdapterAbilityFunc func;
    CfBase *adapterRes;
};

using CfCertObjStruct = CfCertObjStruct_;

/**
 * @tc.name: CfObjectCertTest001
 * @tc.desc: CfCertCreate: in is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest001, TestSize.Level0)
{
    CfBase *obj = nullptr;
    int32_t ret = CfCertCreate(nullptr, &obj); /* in is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectCertTest002
 * @tc.desc: CfCertCreate: obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest002, TestSize.Level0)
{
    int32_t ret = CfCertCreate(&g_cert, nullptr); /* obj is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectCertTest003
 * @tc.desc: CfCertDestroy: obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest003, TestSize.Level0)
{
    CfCertDestroy(nullptr); /* obj is nullptr coverage */
}

/**
 * @tc.name: CfObjectCertTest004
 * @tc.desc: CfCertDestroy: *obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest004, TestSize.Level0)
{
    CfBase *obj = nullptr;
    CfCertDestroy(&obj); /* *obj is nullptr coverage */
}

/**
 * @tc.name: CfObjectCertTest005
 * @tc.desc: CfCertDestroy: baseType magicid invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest005, TestSize.Level0)
{
    CfCertObjStruct certObj;
    (void)memset_s(&certObj, sizeof(certObj), 0, sizeof(certObj));

    certObj.base.type = 0xff; /* baseType magicid invalid */
    CfBase *base = &certObj.base;

    CfCertDestroy(&base);
}

/**
 * @tc.name: CfObjectCertTest006
 * @tc.desc: CfCertCheck: obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest006, TestSize.Level0)
{
    CfParamSet in;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    CfParamSet *out = nullptr;
    int32_t ret = CfCertCheck(nullptr, &in, &out); /* obj is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectCertTest007
 * @tc.desc: CfCertCheck: in is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest007, TestSize.Level0)
{
    CfBase base;
    (void)memset_s(&base, sizeof(base), 0, sizeof(base));
    CfParamSet *out = nullptr;
    int32_t ret = CfCertCheck(&base, nullptr, &out); /* in is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectCertTest008
 * @tc.desc: CfCertCheck: out is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest008, TestSize.Level0)
{
    CfParamSet in;
    CfBase base;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    (void)memset_s(&base, sizeof(base), 0, sizeof(base));
    int32_t ret = CfCertCheck(&base, &in, nullptr); /* out is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectCertTest009
 * @tc.desc: CfCertCheck: baseType magicid invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest009, TestSize.Level0)
{
    CfParamSet in;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    CfParamSet *out = nullptr;

    CfCertObjStruct certObj;
    (void)memset_s(&certObj, sizeof(certObj), 0, sizeof(certObj));
    certObj.base.type = 0xff; /* baseType magicid invalid */

    int32_t ret = CfCertCheck(&certObj.base, &in, &out);
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectCertTest010
 * @tc.desc: CfCertGet: obj is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest010, TestSize.Level0)
{
    CfParamSet in;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    CfParamSet *out = nullptr;
    int32_t ret = CfCertGet(nullptr, &in, &out); /* obj is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectCertTest011
 * @tc.desc: CfCertGet: in is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest011, TestSize.Level0)
{
    CfBase base;
    (void)memset_s(&base, sizeof(base), 0, sizeof(base));
    CfParamSet *out = nullptr;
    int32_t ret = CfCertGet(&base, nullptr, &out); /* in is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectCertTest012
 * @tc.desc: CfCertGet: out is nullptr
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest012, TestSize.Level0)
{
    CfParamSet in;
    CfBase base;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    (void)memset_s(&base, sizeof(base), 0, sizeof(base));
    int32_t ret = CfCertGet(&base, &in, nullptr); /* out is nullptr */
    EXPECT_NE(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfObjectCertTest013
 * @tc.desc: CfCertGet: baseType magicid invalid
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfObjectCertTest, CfObjectCertTest013, TestSize.Level0)
{
    CfParamSet in;
    (void)memset_s(&in, sizeof(in), 0, sizeof(in));
    CfParamSet *out = nullptr;

    CfCertObjStruct certObj;
    (void)memset_s(&certObj, sizeof(certObj), 0, sizeof(certObj));
    certObj.base.type = 0xff; /* baseType magicid invalid */

    int32_t ret = CfCertGet(&certObj.base, &in, &out);
    EXPECT_NE(ret, CF_SUCCESS);
}
}

