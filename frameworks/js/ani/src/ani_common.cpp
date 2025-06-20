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

#include "ani_common.h"
#include <unordered_map>

namespace {
enum ResultCode {
    SUCCESS = 0,
    INVALID_PARAMS = 401,
    NOT_SUPPORT = 801,
    ERR_OUT_OF_MEMORY = 19020001,
    ERR_RUNTIME_ERROR = 19020002,
    ERR_PARAMETER_CHECK_FAILED = 19020003,
    ERR_CRYPTO_OPERATION = 19030001,
    ERR_CERT_SIGNATURE_FAILURE = 19030002,
    ERR_CERT_NOT_YET_VALID = 19030003,
    ERR_CERT_HAS_EXPIRED = 19030004,
    ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 19030005,
    ERR_KEYUSAGE_NO_CERTSIGN = 19030006,
    ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 19030007,
    ERR_MAYBE_WRONG_PASSWORD = 19030008,
};

static const std::unordered_map<CfResult, int> RESULT_CODE = {
    { CF_SUCCESS, SUCCESS },
    { CF_INVALID_PARAMS, INVALID_PARAMS },
    { CF_NOT_SUPPORT, NOT_SUPPORT },
    { CF_ERR_MALLOC, ERR_OUT_OF_MEMORY },
    { CF_ERR_INTERNAL, ERR_RUNTIME_ERROR },
    { CF_ERR_PARAMETER_CHECK, ERR_PARAMETER_CHECK_FAILED },
    { CF_ERR_CRYPTO_OPERATION, ERR_CRYPTO_OPERATION },
    { CF_ERR_CERT_SIGNATURE_FAILURE, ERR_CERT_SIGNATURE_FAILURE },
    { CF_ERR_CERT_NOT_YET_VALID, ERR_CERT_NOT_YET_VALID },
    { CF_ERR_CERT_HAS_EXPIRED, ERR_CERT_HAS_EXPIRED },
    { CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { CF_ERR_KEYUSAGE_NO_CERTSIGN, ERR_KEYUSAGE_NO_CERTSIGN },
    { CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE },
    { CF_ERR_CERT_INVALID_PRIVATE_KEY, ERR_MAYBE_WRONG_PASSWORD },
};
} // namespace

namespace ANI::CertFramework {
int ConvertResultCode(CfResult res)
{
    if (RESULT_CODE.count(res) > 0) {
        return RESULT_CODE.at(res);
    }
    return ERR_RUNTIME_ERROR;
}

void ArrayU8ToDataBlob(const array<uint8_t> &arr, CfBlob &blob)
{
    blob.data = arr.empty() ? nullptr : arr.data();
    blob.size = arr.size();
}

void DataBlobToArrayU8(const CfBlob &blob, array<uint8_t> &arr)
{
    arr = array<uint8_t>(move_data_t{}, blob.data, blob.size);
}

void ArrayU8ToBigInteger(const array<uint8_t> &arr, CfBlob &bigint, bool isReverse /* = false */)
{
    bigint.data = arr.empty() ? nullptr : arr.data();
    bigint.size = arr.size();
    if (bigint.size > 0 && bigint.data[bigint.size - 1] == 0) { // remove the sign bit of big integer
        bigint.size--;
    }
    if (isReverse) { // reverse bigint data for serial number
        std::reverse(bigint.data, bigint.data + bigint.size);
    }
}

void BigIntegerToArrayU8(const CfBlob &bigint, array<uint8_t> &arr, bool isReverse /* = false */)
{
    arr = array<uint8_t>(bigint.size + 1);
    std::copy(bigint.data, bigint.data + bigint.size, arr.data());
    if (isReverse) { // reverse bigint data for serial number
        std::reverse(arr.begin(), arr.begin() + bigint.size);
    }
    // 0x00 is the sign bit of big integer, it's always a positive number in this implementation
    arr[bigint.size] = 0x00;
}

void StringToDataBlob(const string &str, CfBlob &blob)
{
    blob.data = str.empty() ? nullptr : reinterpret_cast<uint8_t *>(const_cast<char *>(str.c_str()));
    blob.size = str.size();
}

void CfArrayToDataArray(const CfArray &cfArr, DataArray &dataArr)
{
    dataArr = { array<array<uint8_t>>::make(cfArr.count, {}) };
    for (uint32_t i = 0; i < cfArr.count; i++) {
        DataBlobToArrayU8(cfArr.data[i], dataArr.data[i]);
    }
}

void DataBlobToEncodingBlob(const CfBlob &blob, CfEncodingBlob &encodingBlob,
    CfEncodingFormat encodingFormat /* = CF_FORMAT_DER */)
{
    encodingBlob.data = blob.data;
    encodingBlob.len = blob.size;
    encodingBlob.encodingFormat = encodingFormat;
}

bool CopyString(const string &str, char **dst)
{
    *dst = static_cast<char *>(CfMalloc(str.size() + 1, 0));
    if (*dst == nullptr) {
        return false;
    }
    if (strcpy_s(*dst, str.size() + 1, str.c_str()) != EOK) {
        CfFree(*dst);
        *dst = nullptr;
        return false;
    }
    return true;
}
} // namespace ANI::CertFramework
