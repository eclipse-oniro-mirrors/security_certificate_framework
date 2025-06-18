/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef ANI_COMMON_H
#define ANI_COMMON_H

#include "stdexcept"
#include "taihe/runtime.hpp"
#include "ohos.security.cert.cert.proj.hpp"
#include "ohos.security.cert.cert.impl.hpp"

#include "cf_api.h"
#include "cf_log.h"
#include "cf_blob.h"
#include "cf_result.h"
#include "cf_memory.h"
#include "cf_object_base.h"

namespace ANI::CertFramework {
using namespace taihe;
using namespace ohos::security::cert::cert;
namespace cryptoFramework = ohos::security::cryptoFramework::cryptoFramework;

#define ANI_LOGE_THROW(code, msg) \
    do { \
        LOGE("%{public}s", msg); \
        set_business_error(ConvertResultCode(code), msg); \
    } while (0)

int ConvertResultCode(CfResult res);

void ArrayU8ToDataBlob(const array<uint8_t> &arr, CfBlob &blob);
void DataBlobToArrayU8(const CfBlob &blob, array<uint8_t> &arr);
void ArrayU8ToBigInteger(const array<uint8_t> &arr, CfBlob &bigInt, bool isReverse = false);
void BigIntegerToArrayU8(const CfBlob &bigInt, array<uint8_t> &arr, bool isReverse = false);
void StringToDataBlob(const string &str, CfBlob &blob);
void CfArrayToDataArray(const CfArray &cfArr, DataArray &dataArr);
void DataBlobToEncodingBlob(const CfBlob &blob, CfEncodingBlob &encodingBlob,
    CfEncodingFormat encodingFormat = CF_FORMAT_DER);
} // namespace ANI::CertFramework

#endif // ANI_COMMON_H
