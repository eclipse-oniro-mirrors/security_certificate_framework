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

#include "cf_ability.h"
#include "cf_cert_adapter_ability_define.h"
#include "cf_magic.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "cf_test_common.h"
#include "cf_test_data.h"

using namespace testing::ext;
using namespace CertframeworkTest;
using namespace CertframeworkTestData;

namespace {
class CfAbilityTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CfAbilityTest::SetUpTestCase(void)
{
}

void CfAbilityTest::TearDownTestCase(void)
{
}

void CfAbilityTest::SetUp()
{
}

void CfAbilityTest::TearDown()
{
}

/**
 * @tc.name: RegisterAbilityTest001
 * @tc.desc: Test RegisterAbility interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAbilityTest, RegisterAbilityTest001, TestSize.Level0)
{
    int32_t ret = RegisterAbility(CF_ABILITY(CF_ABILITY_TYPE_ADAPTER, CF_OBJ_TYPE_CERT), nullptr);
    EXPECT_EQ(ret, CF_NOT_SUPPORT) << "register extension adapter func again, recode:" << ret;
}

/**
 * @tc.name: RegisterAbilityTest002
 * @tc.desc: Test RegisterAbility Exceeds max
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAbilityTest, RegisterAbilityTest002, TestSize.Level0)
{
    for (uint32_t i = 0; i <= CF_ABILITY_MAX_SIZE; ++i) {
        (void)RegisterAbility(i, nullptr); /* coverage test */
    }
}

/**
 * @tc.name: GetAbilityTest001
 * @tc.desc: Test GetAbility interface base function
 * @tc.type: FUNC
 * @tc.require: AR000HS2RB /SR000HS2Q1
 */
HWTEST_F(CfAbilityTest, GetAbilityTest001, TestSize.Level0)
{
    int32_t ret = CF_SUCCESS;
    CfBase *func = GetAbility(CF_ABILITY(CF_ABILITY_TYPE_ADAPTER, CF_OBJ_TYPE_CERT));
    if (func == nullptr) {
        printf("get ability failed\n");
        ret = CF_ERR_CRYPTO_OPERATION;
        ASSERT_EQ(ret, CF_SUCCESS);
    }

    CfCertAdapterAbilityFunc *adapterFunc = (CfCertAdapterAbilityFunc *)func;
    if (adapterFunc->base.type != CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_FUNC, CF_OBJ_TYPE_CERT)) {
        printf("func magic id is %lu\n", adapterFunc->base.type);
        ret = CF_INVALID_PARAMS;
    } else {
        CfBase *obj001 = nullptr;
        CfEncodingBlob cert = { const_cast<uint8_t *>(g_certData01), sizeof(g_certData01), CF_FORMAT_DER };
        ret = adapterFunc->adapterCreate(&cert, &obj001);
        EXPECT_EQ(ret, CF_SUCCESS) << "create cert object failed, recode:" << ret;

        ret = adapterFunc->adapterVerify(nullptr, nullptr);
        EXPECT_EQ(ret, CF_SUCCESS) << "verify cert object failed, recode:" << ret;

        CfBlob tbsBlob = { 0, nullptr };
        ret = adapterFunc->adapterGetItem(obj001, CF_ITEM_TBS, &tbsBlob);
        EXPECT_EQ(ret, CF_SUCCESS) << "get tbs failed, recode:" << ret;
        CF_FREE_BLOB(tbsBlob);

        CfBlob issuerUidBlob = { 0, nullptr };
        ret = adapterFunc->adapterGetItem(obj001, CF_ITEM_ISSUER_UNIQUE_ID, &issuerUidBlob);
        EXPECT_EQ(ret, CF_SUCCESS) << "get issuerUid failed, recode:" << ret;
        CF_FREE_BLOB(issuerUidBlob);

        CfBlob subjectUidBlob = { 0, nullptr };
        ret = adapterFunc->adapterGetItem(obj001, CF_ITEM_SUBJECT_UNIQUE_ID, &subjectUidBlob);
        EXPECT_EQ(ret, CF_SUCCESS) << "get subjectUid failed, recode:" << ret;
        CF_FREE_BLOB(subjectUidBlob);

        CfBlob extsBlob = { 0, nullptr };
        ret = adapterFunc->adapterGetItem(obj001, CF_ITEM_EXTENSIONS, &extsBlob);
        EXPECT_EQ(ret, CF_SUCCESS) << "get extension failed, recode:" << ret;
        CF_FREE_BLOB(extsBlob);

        adapterFunc->adapterDestory(&obj001);
    }
    EXPECT_EQ(ret, CF_SUCCESS) << "adapter function magic id is err, retcode:" << ret;
}
}
