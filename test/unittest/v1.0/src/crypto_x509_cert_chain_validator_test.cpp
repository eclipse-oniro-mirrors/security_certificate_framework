/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "securec.h"
#include "string"

#include "cert_chain_validator.h"
#include "cf_blob.h"
#include "memory_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "crypto_x509_cert_chain_data_pem.h"
#include "crypto_x509_cert_chain_data_pem_added.h"
#include "x509_cert_chain_validator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoX509CertChainValidatorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

constexpr int32_t CERT_HEADER_LEN = 2;
constexpr int32_t INVALID_MAX_CERT_LEN = 8194;


static uint8_t g_certDerFormat[] = {
    0x30, 0x82, 0x05, 0xc1, 0x30, 0x82, 0x03, 0xa9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x05,
    0xf2, 0x86, 0xae, 0xef, 0xff, 0xcb, 0x1b, 0xdd, 0x46, 0x8b, 0xdc, 0xf2, 0x25, 0xbd, 0x53, 0xd7,
    0x73, 0x82, 0xa3, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x6f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43,
    0x49, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x68, 0x6e, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x02, 0x73, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x02, 0x68, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x02, 0x69, 0x69, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02,
    0x61, 0x62, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
    0x01, 0x16, 0x10, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x40, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e,
    0x63, 0x6f, 0x6d, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x38, 0x32, 0x30, 0x31, 0x32, 0x32,
    0x32, 0x33, 0x36, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36, 0x32, 0x30, 0x38, 0x32, 0x30, 0x31, 0x32,
    0x32, 0x32, 0x33, 0x36, 0x5a, 0x30, 0x6f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x43, 0x49, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x68,
    0x6e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x02, 0x73, 0x68, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x02, 0x68, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x0c, 0x02, 0x69, 0x69, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x02, 0x61, 0x62, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x09, 0x01, 0x16, 0x10, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x40, 0x68, 0x65, 0x6c,
    0x6c, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00, 0x30, 0x82,
    0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xe5, 0xe4, 0x71, 0x7e, 0xdc, 0x1e, 0x09, 0x53, 0xc9,
    0x29, 0x78, 0x5e, 0x68, 0xf0, 0x32, 0x18, 0xb2, 0xc6, 0x13, 0x10, 0x51, 0x24, 0xe7, 0x66, 0xd0,
    0x32, 0x8c, 0x88, 0xae, 0x77, 0x22, 0x66, 0xaf, 0xda, 0xba, 0x0a, 0x2f, 0x0e, 0x5c, 0x64, 0xf3,
    0xc8, 0xf2, 0xa6, 0xbc, 0x37, 0xa3, 0xc0, 0xa7, 0x16, 0xab, 0x06, 0x0d, 0xa5, 0x22, 0x6c, 0xb7,
    0x02, 0xd4, 0x97, 0xba, 0x3c, 0x9c, 0x58, 0x08, 0x26, 0x60, 0xbd, 0xce, 0x44, 0x36, 0x67, 0x07,
    0x44, 0xaf, 0x98, 0x03, 0x35, 0xe8, 0x6e, 0x47, 0xd9, 0xcd, 0x8c, 0x3e, 0x79, 0xb5, 0x52, 0x83,
    0xeb, 0xcb, 0x2f, 0xb8, 0xb1, 0x84, 0x59, 0xbc, 0x85, 0x23, 0xd0, 0x0b, 0xf2, 0x9e, 0x7b, 0xf1,
    0x53, 0xd3, 0x7b, 0x1d, 0x7c, 0x2a, 0x72, 0xd8, 0x4e, 0x72, 0x73, 0x62, 0xed, 0xab, 0x56, 0xc9,
    0x45, 0x34, 0x1c, 0xd0, 0x15, 0x53, 0x72, 0x14, 0xf1, 0xa1, 0x6c, 0xdf, 0xd9, 0x11, 0xc9, 0xc4,
    0x20, 0x25, 0xb8, 0xa8, 0x5a, 0x2f, 0xba, 0xa3, 0x5d, 0x58, 0x7f, 0xd1, 0xf7, 0x0b, 0xb2, 0x8a,
    0x51, 0x74, 0xf0, 0x22, 0x63, 0x05, 0xd5, 0xc0, 0x7c, 0x5b, 0xee, 0x92, 0x8a, 0x25, 0x78, 0xcd,
    0xc8, 0xa7, 0xf1, 0x4d, 0x48, 0xd6, 0xf4, 0xca, 0x0b, 0x3d, 0x37, 0xe1, 0xa7, 0xc4, 0xab, 0xb0,
    0xc7, 0x26, 0xdc, 0x80, 0x2f, 0xea, 0x66, 0x53, 0xc7, 0xb6, 0x79, 0x74, 0xdd, 0xe6, 0xc8, 0xef,
    0xf8, 0x11, 0x80, 0xbf, 0x3a, 0xdc, 0x4e, 0xd2, 0x65, 0x1d, 0x65, 0x0c, 0x83, 0x05, 0x43, 0x7e,
    0x7e, 0x67, 0xe4, 0xdc, 0x33, 0x84, 0x8f, 0xa9, 0xba, 0x24, 0x36, 0xbf, 0xa7, 0x0a, 0x25, 0x15,
    0x86, 0x64, 0xd6, 0xe7, 0xaa, 0xd9, 0x25, 0x22, 0xc3, 0x0c, 0xab, 0xf3, 0x1f, 0x34, 0x9b, 0xa2,
    0x7d, 0x5a, 0xb5, 0xde, 0xdb, 0x8e, 0x35, 0x96, 0x0c, 0x0f, 0xc5, 0x91, 0x46, 0x6d, 0xbe, 0x3a,
    0xcf, 0xf8, 0x85, 0x47, 0x7b, 0xe3, 0x1c, 0x39, 0x2d, 0x69, 0x0f, 0x15, 0x0e, 0xc9, 0x4b, 0xfa,
    0xd9, 0x88, 0x91, 0x0f, 0xa5, 0x24, 0x1c, 0x00, 0xc0, 0xa8, 0xad, 0x2c, 0x84, 0x4a, 0x3f, 0x7a,
    0x36, 0xdd, 0xf7, 0x60, 0x91, 0x6e, 0x86, 0xd5, 0x2d, 0xaa, 0x58, 0xf4, 0x62, 0x74, 0x54, 0xea,
    0x25, 0x13, 0x4e, 0xb5, 0x3d, 0xe3, 0x43, 0x8b, 0x2f, 0xdc, 0x30, 0x8d, 0x62, 0x86, 0x16, 0xc1,
    0x6e, 0xae, 0x92, 0xe5, 0x83, 0x7f, 0x9a, 0x78, 0xe0, 0x9f, 0x4c, 0xa5, 0x0c, 0x3f, 0xfa, 0x48,
    0x0e, 0x2b, 0x71, 0xcf, 0x0f, 0x7a, 0x9e, 0xee, 0x6d, 0x74, 0x95, 0xce, 0x1a, 0x7f, 0x9a, 0xe8,
    0x24, 0x26, 0x5b, 0x43, 0xbd, 0x85, 0xa8, 0x4c, 0xef, 0x2b, 0xb5, 0x92, 0x6b, 0xca, 0xa3, 0xfb,
    0x85, 0xe8, 0x69, 0x27, 0xc9, 0x59, 0xd6, 0xc1, 0xa3, 0x94, 0x11, 0x3e, 0xd4, 0x7e, 0x3a, 0xef,
    0x7c, 0x2a, 0xc7, 0xe1, 0xde, 0x19, 0x3a, 0x06, 0xa4, 0x1c, 0x2b, 0x5c, 0xcf, 0xb7, 0x98, 0xa6,
    0xb6, 0xec, 0xa0, 0xcc, 0xb5, 0x24, 0x6d, 0xd0, 0x2b, 0xcb, 0xbb, 0x27, 0x11, 0xd5, 0x22, 0x16,
    0x16, 0x66, 0x57, 0xcb, 0xc9, 0xfc, 0x79, 0x57, 0xa6, 0x78, 0x0e, 0x1d, 0xf5, 0xf9, 0x52, 0x61,
    0xa9, 0x36, 0x32, 0xfe, 0x4f, 0x3d, 0x7b, 0x6d, 0xa5, 0x23, 0x39, 0xf2, 0xbc, 0xa5, 0x23, 0x60,
    0x68, 0x49, 0x32, 0x60, 0xc4, 0xdf, 0xe3, 0xd6, 0xd1, 0x35, 0x2e, 0x8f, 0x21, 0x69, 0xdc, 0x29,
    0x8b, 0x98, 0x3a, 0xf0, 0x7d, 0x05, 0x77, 0x5f, 0x47, 0x38, 0xd7, 0x7e, 0x2c, 0x5c, 0x40, 0x86,
    0x98, 0x09, 0xd9, 0x95, 0x09, 0x6f, 0x7a, 0xa8, 0x1b, 0x2a, 0x44, 0xcb, 0x52, 0x77, 0xdb, 0x61,
    0x42, 0xab, 0xa7, 0x63, 0x22, 0xb2, 0x17, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x47, 0xd9, 0xcb, 0x06, 0xb8,
    0x3f, 0xa4, 0xc2, 0x8e, 0xad, 0x53, 0x4d, 0xeb, 0x55, 0xb4, 0x79, 0x76, 0xd0, 0x61, 0x7e, 0x30,
    0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x47, 0xd9, 0xcb, 0x06,
    0xb8, 0x3f, 0xa4, 0xc2, 0x8e, 0xad, 0x53, 0x4d, 0xeb, 0x55, 0xb4, 0x79, 0x76, 0xd0, 0x61, 0x7e,
    0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
    0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x03, 0x82, 0x02, 0x01, 0x00, 0xa8, 0xbd, 0x7f, 0xb2, 0xe1, 0xf3, 0x76, 0xee, 0x08, 0xcf, 0x66,
    0xe4, 0xf5, 0xc7, 0xc2, 0xdb, 0x9b, 0x57, 0x3a, 0x50, 0xf7, 0x2b, 0x69, 0x63, 0x94, 0xc7, 0x97,
    0xd0, 0xab, 0xb8, 0x29, 0x6f, 0x11, 0xa1, 0x91, 0x6b, 0xdc, 0x35, 0x60, 0xc4, 0x33, 0xa1, 0x43,
    0xf5, 0xb3, 0x48, 0x4f, 0x7a, 0x00, 0xd1, 0x88, 0xa2, 0x52, 0xa3, 0xd5, 0x38, 0x6f, 0xb6, 0xa5,
    0x88, 0x83, 0x13, 0x0b, 0x10, 0x25, 0xbc, 0x20, 0xac, 0x76, 0x66, 0x40, 0x86, 0x1a, 0xb9, 0xf3,
    0x19, 0x7a, 0xf3, 0xbe, 0x6b, 0x92, 0x38, 0xbb, 0xa1, 0x47, 0xb6, 0xd8, 0xf4, 0xe7, 0xf8, 0xee,
    0x67, 0xf8, 0xf9, 0xc5, 0x51, 0x02, 0x51, 0x62, 0x29, 0x18, 0x52, 0x25, 0xfa, 0xaf, 0x54, 0xf0,
    0x1e, 0x5d, 0x67, 0xb1, 0x9b, 0x23, 0x9c, 0xcc, 0x35, 0x9f, 0xa4, 0xd7, 0xf2, 0x96, 0xb7, 0xee,
    0xb1, 0xe7, 0x3a, 0x91, 0x61, 0x4d, 0x72, 0xb3, 0x19, 0x71, 0x21, 0x3a, 0x24, 0x55, 0xfc, 0xea,
    0x06, 0xef, 0xc3, 0xb4, 0xc1, 0xaa, 0xb2, 0xbc, 0x37, 0xe8, 0x5a, 0x86, 0x11, 0x55, 0x1c, 0xd2,
    0x46, 0x07, 0x19, 0x6f, 0x60, 0xc2, 0xc3, 0x4b, 0x5e, 0x6c, 0x3e, 0x60, 0xca, 0x50, 0x32, 0x29,
    0xc0, 0x38, 0x4f, 0x2e, 0x53, 0x43, 0xf0, 0xf3, 0x0b, 0x50, 0x79, 0x7f, 0x54, 0x70, 0x0f, 0x9b,
    0x51, 0xd3, 0xf8, 0xbf, 0xd4, 0x7b, 0x62, 0x41, 0x2d, 0x13, 0x7a, 0xdf, 0x50, 0x26, 0x75, 0xa6,
    0x29, 0x44, 0x10, 0x1e, 0x57, 0xa2, 0x49, 0x4e, 0x3e, 0x7e, 0x87, 0x63, 0x00, 0x21, 0xad, 0x20,
    0x7c, 0x81, 0xbd, 0x40, 0xaf, 0xc8, 0x26, 0x2d, 0x47, 0x1b, 0x3b, 0x40, 0x53, 0xf3, 0x9c, 0x92,
    0xa0, 0xf2, 0xc9, 0x73, 0x0f, 0xe6, 0xf1, 0x71, 0x42, 0xf0, 0x38, 0xfd, 0x64, 0x55, 0x36, 0xe6,
    0xec, 0x78, 0x96, 0x1b, 0xf0, 0x99, 0x1b, 0x3d, 0x1c, 0x51, 0x5c, 0x05, 0x42, 0x6d, 0x63, 0x10,
    0x75, 0xdd, 0x47, 0x5f, 0xaa, 0x51, 0x53, 0x02, 0x56, 0x5d, 0xb4, 0xf5, 0xa2, 0xd3, 0x42, 0x10,
    0x0b, 0xb3, 0x2e, 0x8d, 0x5d, 0x22, 0x8e, 0x84, 0x7a, 0x3e, 0x79, 0xed, 0xc2, 0x90, 0x61, 0x2c,
    0x72, 0x2b, 0xcb, 0x55, 0xd9, 0xc7, 0x39, 0x2b, 0x1e, 0x6b, 0x89, 0x19, 0x0b, 0x99, 0x3b, 0xb4,
    0xda, 0x7f, 0xd1, 0x72, 0x6e, 0x5a, 0xf2, 0x74, 0x8a, 0x6b, 0x91, 0x1c, 0x8b, 0x65, 0x14, 0xa3,
    0xaf, 0x78, 0xf5, 0xbd, 0xaf, 0xda, 0x9a, 0x16, 0x59, 0x65, 0xe2, 0x99, 0xbb, 0x50, 0x3c, 0x28,
    0xb9, 0x93, 0x2b, 0xf5, 0x45, 0xd4, 0x85, 0x3c, 0x7f, 0xdb, 0xcc, 0x05, 0xb9, 0xab, 0x23, 0xa4,
    0x71, 0xd2, 0x18, 0x26, 0xc0, 0xea, 0xf8, 0x91, 0x57, 0xb1, 0x0d, 0xd2, 0xb2, 0x86, 0xe6, 0x70,
    0x53, 0x4b, 0xb4, 0x1e, 0xa2, 0x4c, 0x25, 0x1d, 0x55, 0x8a, 0x7f, 0x77, 0x20, 0x53, 0x11, 0x13,
    0xad, 0xe1, 0x8c, 0xd9, 0xe8, 0xdc, 0xd3, 0xcb, 0xed, 0xdd, 0x26, 0x96, 0x19, 0xb0, 0x8c, 0x4c,
    0xb0, 0xad, 0x8d, 0x0c, 0x99, 0x76, 0x22, 0x43, 0xa6, 0xa0, 0xf2, 0x8d, 0x0f, 0x60, 0x05, 0xe0,
    0x36, 0xbf, 0x0d, 0xc4, 0xe1, 0x2f, 0x05, 0x8e, 0xd9, 0x3a, 0x45, 0x9d, 0xd9, 0xd7, 0x89, 0x23,
    0x20, 0x11, 0x0c, 0x47, 0x3d, 0x9c, 0xf7, 0x18, 0xe3, 0xa3, 0x22, 0xc2, 0x8c, 0x09, 0xe9, 0xb3,
    0xcc, 0x54, 0xf0, 0x97, 0x60, 0x63, 0xb1, 0x49, 0xf4, 0x69, 0xbd, 0x8e, 0x52, 0x12, 0x38, 0x23,
    0x96, 0x55, 0x67, 0x2b, 0x75, 0x0b, 0x20, 0xcd, 0xc0, 0x7d, 0x5a, 0x83, 0x7b, 0xb9, 0xf7, 0x1a,
    0x70, 0xf8, 0xa4, 0x76, 0xc7, 0x65, 0x03, 0xcb, 0x1a, 0x9a, 0xb4, 0x6d, 0x01, 0xfd, 0x25, 0x49,
    0xc2, 0xad, 0xa0, 0x7a, 0xd2
};

static uint8_t g_secCertDerFormat[] = {
    0x30, 0x82, 0x05, 0xbc, 0x30, 0x82, 0x03, 0xa4, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x64,
    0x36, 0x52, 0x81, 0xa9, 0xfb, 0xb4, 0x5b, 0xe6, 0x78, 0xc9, 0x94, 0x0f, 0xcd, 0x24, 0x93, 0xea,
    0x29, 0x39, 0x9c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x6f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43,
    0x49, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x68, 0x6e, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x02, 0x73, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x02, 0x68, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x02, 0x69, 0x69, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x02,
    0x61, 0x62, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
    0x01, 0x16, 0x10, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x40, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e,
    0x63, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x38, 0x32, 0x30, 0x31, 0x32, 0x32,
    0x38, 0x30, 0x38, 0x5a, 0x17, 0x0d, 0x34, 0x32, 0x30, 0x38, 0x32, 0x30, 0x31, 0x32, 0x32, 0x38,
    0x30, 0x38, 0x5a, 0x30, 0x7c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x43, 0x4e, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x05, 0x48, 0x55, 0x4e,
    0x41, 0x4e, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x08, 0x53, 0x48, 0x41,
    0x47, 0x4e, 0x48, 0x41, 0x49, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x02,
    0x68, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x02, 0x69, 0x69, 0x31,
    0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72,
    0x31, 0x1f, 0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16,
    0x10, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x40, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x63, 0x6f,
    0x6d, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02,
    0x01, 0x00, 0xb9, 0x25, 0x72, 0xae, 0x5b, 0x02, 0xe6, 0x73, 0xbe, 0xeb, 0x89, 0x93, 0x60, 0x60,
    0x15, 0x25, 0xbd, 0x5b, 0x75, 0x12, 0x61, 0xcf, 0xb0, 0x13, 0x33, 0x2d, 0x82, 0x13, 0x60, 0x02,
    0xca, 0x8f, 0xd1, 0x02, 0x5d, 0xa9, 0xe1, 0x8a, 0x33, 0xf2, 0xe2, 0x7a, 0x53, 0x6d, 0xc8, 0xa7,
    0x81, 0x7e, 0x1e, 0x60, 0x06, 0xa9, 0x79, 0xc8, 0x44, 0x67, 0xb3, 0xc1, 0xbf, 0x94, 0xd5, 0x76,
    0x8c, 0x93, 0x15, 0xfa, 0x58, 0x94, 0x32, 0x6e, 0x78, 0x1b, 0x62, 0x17, 0x49, 0x5f, 0x40, 0x2c,
    0xac, 0x49, 0x73, 0xd8, 0x26, 0x6c, 0x87, 0x46, 0x44, 0xf5, 0xbb, 0x1f, 0x01, 0xa9, 0x29, 0x32,
    0xd4, 0xab, 0x0a, 0x6e, 0xd1, 0x0a, 0xe7, 0x07, 0xc4, 0x30, 0xfd, 0x47, 0xa5, 0x83, 0x58, 0xed,
    0xa9, 0xdc, 0x04, 0x6a, 0xf1, 0x06, 0xe6, 0x2c, 0xf9, 0x3a, 0x33, 0x4b, 0x65, 0xf4, 0x86, 0xe8,
    0xe3, 0x2f, 0xe7, 0x27, 0xce, 0x2b, 0xbc, 0xd7, 0xc4, 0x92, 0x38, 0x15, 0x36, 0x75, 0xa1, 0xdc,
    0x92, 0xc9, 0xf1, 0xaf, 0x4e, 0x9d, 0xa3, 0xc1, 0x9b, 0xed, 0xe3, 0xff, 0x57, 0xcf, 0x87, 0x37,
    0x13, 0x02, 0x8e, 0x55, 0x01, 0x7c, 0xc4, 0x71, 0x4a, 0x26, 0xc6, 0x85, 0x7f, 0x25, 0x97, 0x54,
    0x0d, 0xcd, 0x2e, 0x16, 0x3a, 0x95, 0x78, 0x6f, 0x6c, 0xbc, 0xc1, 0x31, 0xd1, 0xd6, 0xe7, 0xff,
    0x16, 0x2b, 0x3e, 0x6d, 0xce, 0xca, 0x09, 0x8d, 0x8e, 0x66, 0xf0, 0xb9, 0x69, 0x14, 0xf7, 0x0c,
    0x75, 0x68, 0x10, 0xc1, 0xd2, 0x4e, 0x44, 0xc1, 0x9d, 0xa9, 0x11, 0xa8, 0x2e, 0xb3, 0xb5, 0x9b,
    0x43, 0x1d, 0xfb, 0x32, 0xbc, 0xaf, 0x2c, 0x83, 0x19, 0x22, 0x53, 0x9f, 0xa8, 0x29, 0xf2, 0x83,
    0x08, 0xb8, 0xef, 0xc1, 0x4b, 0x0f, 0x63, 0x25, 0xd3, 0xed, 0x52, 0xff, 0x75, 0x50, 0x47, 0xc4,
    0xb8, 0x32, 0x9b, 0x65, 0x3e, 0xb9, 0x69, 0x7c, 0xdb, 0x64, 0x16, 0xe8, 0x79, 0x22, 0x7f, 0xe5,
    0x12, 0x03, 0x77, 0xe3, 0x42, 0x3c, 0x71, 0xd4, 0x1f, 0xbf, 0x86, 0x45, 0x95, 0x9d, 0x41, 0x70,
    0x58, 0x73, 0xd3, 0xd3, 0x18, 0x24, 0x5a, 0x3e, 0xb6, 0x84, 0x26, 0xeb, 0x6b, 0xa6, 0xa1, 0x91,
    0x41, 0x74, 0x7e, 0xfa, 0xc3, 0x2e, 0xb7, 0xe0, 0x51, 0x9b, 0xd4, 0x99, 0x61, 0x26, 0xfe, 0xaf,
    0x32, 0x0b, 0xb2, 0x33, 0xc4, 0x14, 0x4d, 0x8b, 0x05, 0xf4, 0xd0, 0x4b, 0x5c, 0xaa, 0x93, 0xe4,
    0x6b, 0x6e, 0x88, 0xae, 0x29, 0x6a, 0xac, 0x30, 0x88, 0xdc, 0xff, 0x9a, 0xee, 0xee, 0x95, 0xfc,
    0x40, 0xc0, 0xa8, 0x76, 0xbb, 0x92, 0x62, 0xc3, 0x4c, 0x5d, 0xf9, 0x00, 0x8d, 0x36, 0x4d, 0xdd,
    0x8b, 0x72, 0x9c, 0x87, 0x1d, 0x19, 0xb6, 0x89, 0xa3, 0xbe, 0x61, 0xd0, 0x87, 0x9e, 0xce, 0x65,
    0x14, 0x5f, 0x3b, 0x79, 0x4d, 0xa6, 0x59, 0xee, 0x8d, 0xdf, 0x7f, 0xe2, 0x89, 0x68, 0x3f, 0xe3,
    0x78, 0xc4, 0x66, 0x7d, 0x52, 0x49, 0xf0, 0xf4, 0xa1, 0xfe, 0x5f, 0x1d, 0x15, 0x67, 0x2e, 0xbc,
    0xd6, 0x5b, 0xb2, 0x69, 0x6d, 0x81, 0xb4, 0x42, 0x9c, 0xdc, 0xae, 0x6f, 0x70, 0x50, 0x40, 0xb7,
    0xc1, 0x52, 0x48, 0x06, 0x29, 0xf7, 0xf6, 0xc9, 0x6e, 0xa7, 0xd7, 0x34, 0x80, 0xcb, 0x3c, 0x9a,
    0x20, 0x43, 0xc1, 0x0a, 0xb1, 0xc7, 0x0e, 0x7e, 0xcf, 0xc8, 0x88, 0xc0, 0xcf, 0xdd, 0x68, 0x2d,
    0x4f, 0x7b, 0xf5, 0x0a, 0xbe, 0xfa, 0xcf, 0xe7, 0x5b, 0x06, 0x8d, 0x39, 0x7c, 0x77, 0xb0, 0xde,
    0x7d, 0x98, 0xe5, 0x24, 0xc2, 0x9f, 0x19, 0xf1, 0xc6, 0xd8, 0x7f, 0x8e, 0x8e, 0x7d, 0x6c, 0xee,
    0x88, 0x79, 0x48, 0x4d, 0xfa, 0x47, 0xe7, 0x9c, 0xa1, 0x80, 0xee, 0xec, 0x70, 0x3e, 0x9a, 0x64,
    0xfc, 0x21, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x43, 0x30, 0x41, 0x30, 0x0c, 0x06, 0x03, 0x55,
    0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x31, 0x06, 0x03, 0x55, 0x1d, 0x1f,
    0x04, 0x2a, 0x30, 0x28, 0x30, 0x26, 0xa0, 0x24, 0xa0, 0x22, 0x86, 0x20, 0x68, 0x74, 0x74, 0x70,
    0x73, 0x3a, 0x2f, 0x2f, 0x63, 0x61, 0x2e, 0x78, 0x69, 0x65, 0x78, 0x69, 0x61, 0x6e, 0x62, 0x69,
    0x6e, 0x2e, 0x63, 0x6e, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x70, 0x65, 0x6d, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00,
    0x29, 0x50, 0x7b, 0x20, 0x86, 0x76, 0x58, 0x74, 0xaf, 0x44, 0xb9, 0xe4, 0x32, 0x46, 0x83, 0x74,
    0x8b, 0xb7, 0xee, 0x5e, 0xb4, 0x54, 0xc8, 0x63, 0xef, 0xd3, 0x1f, 0x39, 0x34, 0xc8, 0xff, 0x40,
    0x9c, 0x67, 0x4a, 0x7c, 0x1b, 0xe7, 0xea, 0x38, 0xa1, 0x93, 0x0a, 0xd3, 0x93, 0x14, 0xb7, 0xf3,
    0x9d, 0x70, 0xa0, 0x0c, 0xe6, 0x07, 0xf4, 0x5e, 0x6d, 0xba, 0x02, 0xcb, 0x77, 0xd0, 0x7b, 0x16,
    0x22, 0xf2, 0xb3, 0x97, 0x81, 0x75, 0x74, 0x72, 0x9b, 0x6d, 0x81, 0x1e, 0xcf, 0xe3, 0xb7, 0x35,
    0x17, 0x16, 0xbc, 0x52, 0x15, 0x60, 0x61, 0xc6, 0xf5, 0xb4, 0x73, 0x00, 0xb0, 0xcb, 0x9f, 0x60,
    0xe5, 0xcf, 0xef, 0x5f, 0x74, 0x1c, 0xbe, 0x58, 0x89, 0x7e, 0x36, 0x8b, 0xab, 0xae, 0xc2, 0xc0,
    0x72, 0x1d, 0x2a, 0x52, 0xa8, 0x72, 0x88, 0x09, 0xa7, 0x5a, 0x9e, 0x44, 0xec, 0xbb, 0x1d, 0xf2,
    0xd0, 0x31, 0x02, 0x47, 0x13, 0xf1, 0x5c, 0xdf, 0x44, 0x19, 0x5e, 0x9e, 0x5b, 0x25, 0xc9, 0xa0,
    0x28, 0x36, 0x06, 0x76, 0xfa, 0xe0, 0x28, 0x6a, 0x73, 0x81, 0xfe, 0x33, 0x8c, 0xe6, 0x07, 0xf8,
    0xe3, 0x21, 0xc0, 0x1d, 0x86, 0xf4, 0xd7, 0x7a, 0x7a, 0x7e, 0xd3, 0x0a, 0x28, 0x6a, 0xdc, 0x0f,
    0x07, 0x88, 0x68, 0xfe, 0x33, 0x73, 0xb3, 0xac, 0xa8, 0x16, 0x47, 0x8a, 0xa2, 0x1e, 0x63, 0xe0,
    0xdd, 0x25, 0xfb, 0x9e, 0x33, 0xcb, 0x3d, 0x57, 0xab, 0x97, 0x2f, 0xa8, 0xf2, 0x88, 0x76, 0xa5,
    0x2c, 0x31, 0x48, 0xb4, 0x0c, 0x2a, 0x03, 0xc7, 0xa5, 0xbb, 0xcc, 0x1c, 0x8a, 0xf9, 0xbd, 0x12,
    0x00, 0x92, 0x51, 0xa0, 0xd9, 0x33, 0xfb, 0x59, 0x5e, 0x7e, 0x59, 0xcf, 0x8c, 0x0b, 0xe2, 0xec,
    0x7d, 0x9e, 0x4c, 0xed, 0x64, 0x99, 0x58, 0x3e, 0x81, 0x57, 0x65, 0xc8, 0x1c, 0x0d, 0xa2, 0x33,
    0x73, 0x7b, 0xc1, 0x8c, 0xef, 0x1f, 0x49, 0x4d, 0x96, 0x04, 0x75, 0x3e, 0xef, 0x2f, 0x85, 0xf9,
    0x4f, 0x7d, 0x28, 0xc5, 0xa2, 0xe2, 0x0b, 0x6c, 0x41, 0xe7, 0xb2, 0x89, 0x07, 0x3e, 0xc5, 0x1d,
    0x6f, 0x19, 0xcd, 0x98, 0xec, 0x8c, 0xa4, 0x20, 0xc2, 0x83, 0x77, 0x23, 0xb9, 0x96, 0x08, 0xca,
    0x30, 0x08, 0x07, 0xf3, 0xa8, 0x00, 0x30, 0x1e, 0x90, 0x01, 0xd7, 0xdd, 0xc0, 0x22, 0xb4, 0x10,
    0x73, 0xcc, 0x3f, 0x4c, 0x04, 0xaf, 0xd4, 0x5d, 0x19, 0x0c, 0x75, 0xe7, 0x7a, 0x25, 0x5c, 0x1f,
    0x6d, 0x91, 0xaa, 0xfb, 0x62, 0xcb, 0x37, 0x35, 0xf3, 0xa8, 0xc5, 0x90, 0x78, 0x27, 0x06, 0xa1,
    0xc4, 0x47, 0x89, 0x5f, 0xbb, 0xbb, 0x0d, 0xe4, 0x94, 0xb0, 0x0d, 0x7c, 0x5f, 0x4d, 0xc9, 0x7b,
    0xd6, 0xe8, 0x56, 0x0d, 0xe7, 0x42, 0xe1, 0x9e, 0x8a, 0xe8, 0x1b, 0x0b, 0x2e, 0x19, 0xeb, 0x58,
    0xdb, 0x61, 0x7f, 0xf2, 0xcd, 0x4d, 0xd2, 0x80, 0xbb, 0x51, 0xc9, 0xff, 0x26, 0x66, 0x54, 0x03,
    0xdc, 0x63, 0x68, 0x20, 0xc4, 0x7a, 0x84, 0xc3, 0xa1, 0xe7, 0xef, 0xf3, 0xfd, 0xf3, 0x4a, 0xbd,
    0xac, 0x47, 0xac, 0x11, 0xee, 0x12, 0x07, 0x82, 0xf0, 0xbd, 0x34, 0xd3, 0x93, 0xcd, 0xd4, 0x92,
    0x46, 0xa7, 0x37, 0x01, 0xf5, 0x33, 0xf7, 0x49, 0x1d, 0xb0, 0x0a, 0x19, 0xa3, 0x0a, 0xa5, 0xec,
    0x2a, 0xd9, 0xcb, 0xb2, 0xe2, 0xab, 0x36, 0x89, 0x33, 0x2d, 0x45, 0xfb, 0x61, 0xfc, 0x8e, 0x6c,
    0xdf, 0x09, 0x5e, 0x83, 0x05, 0xa0, 0x98, 0x83, 0x39, 0x41, 0x19, 0x2f, 0xdd, 0xab, 0xf4, 0x3b,
    0x03, 0xd9, 0x1b, 0x66, 0xb7, 0xc2, 0x79, 0xbf, 0xf2, 0x12, 0x0c, 0xf4, 0x87, 0x42, 0xeb, 0x5a,
    0x70, 0x56, 0xc3, 0x0e, 0xeb, 0xd9, 0x3f, 0x87, 0x93, 0x82, 0xd0, 0xfe, 0x32, 0xed, 0x0b, 0x54,
};

static uint8_t g_invalidCert0[] = {
    0x30, 0x82, 0x03, 0xc1, 0x30, 0x82, 0x03, 0xa9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x05,
};

static HcfCertChainValidator *g_validator = nullptr;

void CryptoX509CertChainValidatorTest::SetUpTestCase()
{
    (void)HcfCertChainValidatorCreate("PKIX", &g_validator);
}
void CryptoX509CertChainValidatorTest::TearDownTestCase()
{
    CfObjDestroy(g_validator);
}

void CryptoX509CertChainValidatorTest::SetUp()
{
}

void CryptoX509CertChainValidatorTest::TearDown()
{
}

HWTEST_F(CryptoX509CertChainValidatorTest, GetAlgorithm001, TestSize.Level0)
{
    const char *algo = g_validator->getAlgorithm(g_validator);
    ASSERT_NE(algo, nullptr);
    string st("PKIX");
    ASSERT_STREQ(algo, st.c_str());
}

HWTEST_F(CryptoX509CertChainValidatorTest, GetAlgorithm002, TestSize.Level0)
{
    HcfCertChainValidator *pathValidator = nullptr;
    CfResult res = HcfCertChainValidatorCreate("invalidPKIX", &pathValidator);
    EXPECT_EQ(res, CF_NOT_SUPPORT);
    EXPECT_EQ(pathValidator, nullptr);

    char inputAlg[1025] = {0}; /* 1025: size bigger than max */
    for (uint32_t i = 0; i < sizeof(inputAlg); ++i) {
        inputAlg[i] = 'c';
    }
    res = HcfCertChainValidatorCreate(inputAlg, &pathValidator);
    EXPECT_NE(res, CF_SUCCESS);
}

/* valid cert chain. */
HWTEST_F(CryptoX509CertChainValidatorTest, VerifyTest001, TestSize.Level0)
{
    CfResult res = CF_SUCCESS;
    HcfCertChainData certsData = { 0 };
    certsData.format = CF_FORMAT_PEM;
    certsData.count = 2; /* level-2 cert chain. */
    uint32_t caCertLen = strlen(g_testCertChainValidatorCaCert) + 1;
    uint32_t secondCaCertLen = strlen(g_testCertChainValidatorSecondCaCert) + 1;
    certsData.dataLen = CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN + caCertLen;
    certsData.data = (uint8_t *)malloc(certsData.dataLen);
    ASSERT_NE(certsData.data, nullptr);
    if (memcpy_s(certsData.data, CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN + caCertLen,
        &secondCaCertLen, CERT_HEADER_LEN) != EOK) {
        goto OUT;
    }
    if (memcpy_s(certsData.data + CERT_HEADER_LEN, secondCaCertLen + CERT_HEADER_LEN + caCertLen,
        g_testCertChainValidatorSecondCaCert, secondCaCertLen) != EOK) {
        goto OUT;
    }
    if (memcpy_s(certsData.data + CERT_HEADER_LEN + secondCaCertLen, CERT_HEADER_LEN + caCertLen,
        &caCertLen, CERT_HEADER_LEN) != EOK) {
        goto OUT;
    }
    if (memcpy_s(certsData.data + CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN, caCertLen,
        g_testCertChainValidatorCaCert, caCertLen) != EOK) {
        goto OUT;
    }

    res = g_validator->validate(g_validator, &certsData);
    EXPECT_EQ(res, CF_SUCCESS);
OUT:
    free(certsData.data);
}

/* invalid cert chain. */
HWTEST_F(CryptoX509CertChainValidatorTest, VerifyTest002, TestSize.Level0)
{
    CfResult res = CF_SUCCESS;
    HcfCertChainData certsData = { 0 };
    certsData.format = CF_FORMAT_PEM;
    certsData.count = 3; /* level-3 cert chain. */
    uint32_t caCertLen = strlen(g_testCertChainValidatorCaCert) + 1;
    uint32_t secondCaCertLen = strlen(g_testCertChainValidatorSecondCaCert) + 1;
    uint32_t thirdCertLen = strlen(g_testCertChainValidatorInvalidCaCert) + 1;
    certsData.dataLen = CERT_HEADER_LEN + thirdCertLen + CERT_HEADER_LEN +
        secondCaCertLen + CERT_HEADER_LEN + caCertLen;
    certsData.data = (uint8_t *)malloc(certsData.dataLen);
    ASSERT_NE(certsData.data, nullptr);
    if (memcpy_s(certsData.data,
        CERT_HEADER_LEN + thirdCertLen + CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN + caCertLen,
        &thirdCertLen, CERT_HEADER_LEN) != EOK) {
        goto OUT;
    }
    if (memcpy_s(certsData.data + CERT_HEADER_LEN,
        thirdCertLen + CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN + caCertLen,
        g_testCertChainValidatorInvalidCaCert, thirdCertLen) != EOK) {
        return;
    }
    if (memcpy_s(certsData.data + CERT_HEADER_LEN + thirdCertLen,
        CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN + caCertLen, &secondCaCertLen, CERT_HEADER_LEN) != EOK) {
        goto OUT;
    }
    if (memcpy_s(certsData.data + CERT_HEADER_LEN + thirdCertLen + CERT_HEADER_LEN,
        secondCaCertLen + CERT_HEADER_LEN + caCertLen, g_testCertChainValidatorSecondCaCert, secondCaCertLen) != EOK) {
        goto OUT;
    }
    if (memcpy_s(certsData.data + CERT_HEADER_LEN + thirdCertLen + CERT_HEADER_LEN + secondCaCertLen,
        CERT_HEADER_LEN + caCertLen, &caCertLen, CERT_HEADER_LEN) != EOK) {
        goto OUT;
    }
    if (memcpy_s(certsData.data + CERT_HEADER_LEN + thirdCertLen + CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN,
        caCertLen, g_testCertChainValidatorCaCert, caCertLen) != EOK) {
        goto OUT;
    }

    res = g_validator->validate(g_validator, &certsData);
    EXPECT_NE(res, CF_SUCCESS);
OUT:
    free(certsData.data);
}

/* invalid cert chain data len. */
HWTEST_F(CryptoX509CertChainValidatorTest, VerifyTest003, TestSize.Level0)
{
    HcfCertChainData certsData = { 0 };
    certsData.format = CF_FORMAT_PEM;
    certsData.count = 3; /* level-3 cert chain. */
    certsData.dataLen = INVALID_MAX_CERT_LEN;
    certsData.data = (uint8_t *)malloc(certsData.dataLen);
    ASSERT_NE(certsData.data, nullptr);

    CfResult res = g_validator->validate(g_validator, &certsData);
    EXPECT_NE(res, CF_SUCCESS);
    free(certsData.data);
}

/* invalid cert number(1). */
HWTEST_F(CryptoX509CertChainValidatorTest, VerifyTest004, TestSize.Level0)
{
    CfResult res = CF_SUCCESS;
    HcfCertChainData certsData = { 0 };
    certsData.format = CF_FORMAT_PEM;
    certsData.count = 1; /* level-3 cert chain. */
    uint32_t caCertLen = strlen(g_testCertChainValidatorCaCert) + 1;
    certsData.dataLen = CERT_HEADER_LEN + caCertLen;
    certsData.data = (uint8_t *)malloc(certsData.dataLen);
    ASSERT_NE(certsData.data, nullptr);
    if (memcpy_s(certsData.data,
        CERT_HEADER_LEN + caCertLen, &caCertLen, CERT_HEADER_LEN) != EOK) {
        goto OUT;
    }
    if (memcpy_s(certsData.data + CERT_HEADER_LEN,
        caCertLen, g_testCertChainValidatorCaCert, caCertLen) != EOK) {
        goto OUT;
    }

    res = g_validator->validate(g_validator, &certsData);
    EXPECT_NE(res, CF_SUCCESS);
OUT:
    free(certsData.data);
}

static int32_t ConstructCertData(HcfCertChainData *certsData, uint8_t *caCert, uint32_t caCertLen,
    uint8_t *secCaCert, uint32_t secCaCertLen)
{
    uint32_t size = CERT_HEADER_LEN + secCaCertLen + CERT_HEADER_LEN + caCertLen;
    uint8_t *tmp = (uint8_t *)malloc(size);
    if (tmp == nullptr) {
        return CF_ERR_MALLOC;
    }

    int32_t ret = CF_ERR_COPY;
    do {
        uint32_t offset = 0;
        if (memcpy_s(tmp + offset, size - offset, &secCaCertLen, CERT_HEADER_LEN) != EOK) {
            break;
        }
        offset += CERT_HEADER_LEN;
        if (memcpy_s(tmp + offset, size - offset, secCaCert, secCaCertLen) != EOK) {
            break;
        }
        offset += secCaCertLen;
        if (memcpy_s(tmp + offset, size - offset, &caCertLen, CERT_HEADER_LEN) != EOK) {
            break;
        }
        offset += CERT_HEADER_LEN;
        if (memcpy_s(tmp + offset, size - offset, caCert, caCertLen) != EOK) {
            break;
        }
        certsData->data = tmp;
        certsData->dataLen = size;
        return CF_SUCCESS;
    } while (0);
    free(tmp);
    return ret;
}

/* valid cert chain der format. */
HWTEST_F(CryptoX509CertChainValidatorTest, VerifyTest005, TestSize.Level0)
{
    HcfCertChainData certsData = { 0 };
    certsData.format = CF_FORMAT_DER;
    certsData.count = 2; /* level-2 cert chain. */

    uint32_t caCertLen = sizeof(g_certDerFormat);
    uint32_t secondCaCertLen = sizeof(g_secCertDerFormat);
    int32_t ret = ConstructCertData(&certsData, g_certDerFormat, caCertLen, g_secCertDerFormat, secondCaCertLen);
    ASSERT_EQ(ret, CF_SUCCESS);

    ret = g_validator->validate(g_validator, &certsData);
    EXPECT_EQ(ret, CF_SUCCESS);
    free(certsData.data);
}

/* valid cert chain format. */
HWTEST_F(CryptoX509CertChainValidatorTest, VerifyTest006, TestSize.Level0)
{
    HcfCertChainData certsData = { 0 };
    certsData.format = static_cast<enum CfEncodingFormat>(CF_FORMAT_PEM + 1);
    certsData.count = 2; /* level-2 cert chain. */

    uint32_t caCertLen = sizeof(g_certDerFormat);
    uint32_t secondCaCertLen = sizeof(g_secCertDerFormat);
    int32_t ret = ConstructCertData(&certsData, g_certDerFormat, caCertLen, g_secCertDerFormat, secondCaCertLen);
    ASSERT_EQ(ret, CF_SUCCESS);

    ret = g_validator->validate(g_validator, &certsData);
    EXPECT_NE(ret, CF_SUCCESS);
    free(certsData.data);
}

/* invalid cert 0. */
HWTEST_F(CryptoX509CertChainValidatorTest, VerifyTest007, TestSize.Level0)
{
    HcfCertChainData certsData = { 0 };
    certsData.format = CF_FORMAT_DER;
    certsData.count = 2; /* level-2 cert chain. */

    uint32_t caCertLen = sizeof(g_invalidCert0);
    uint32_t secondCaCertLen = sizeof(g_secCertDerFormat);
    int32_t ret = ConstructCertData(&certsData, g_invalidCert0, caCertLen, g_secCertDerFormat, secondCaCertLen);
    ASSERT_EQ(ret, CF_SUCCESS);

    ret = g_validator->validate(g_validator, &certsData);
    EXPECT_NE(ret, CF_SUCCESS);
    free(certsData.data);
}

static const char *GetInvalidValidatorClass(void)
{
    return "INVALID_VALIDATOR_CLASS";
}

HWTEST_F(CryptoX509CertChainValidatorTest, NullInput, TestSize.Level0)
{
    CfResult res = HcfCertChainValidatorCreate("PKIX", nullptr);
    EXPECT_NE(res, CF_SUCCESS);
    res = g_validator->validate(nullptr, nullptr);
    EXPECT_NE(res, CF_SUCCESS);
    res = g_validator->validate(g_validator, nullptr);
    EXPECT_NE(res, CF_SUCCESS);
    const char *algo = g_validator->getAlgorithm(nullptr);
    EXPECT_EQ(algo, nullptr);
    (void)g_validator->base.destroy(nullptr);
}

HWTEST_F(CryptoX509CertChainValidatorTest, InvalidClass, TestSize.Level0)
{
    HcfCertChainValidator invalidValidator;
    invalidValidator.base.getClass = GetInvalidValidatorClass;
    HcfCertChainData certsData = { 0 };
    CfResult res = g_validator->validate(&invalidValidator, &certsData);
    EXPECT_NE(res, CF_SUCCESS);
    const char *algo = g_validator->getAlgorithm(&invalidValidator);
    EXPECT_EQ(algo, nullptr);
    (void)g_validator->base.destroy(&(invalidValidator.base));
}

HWTEST_F(CryptoX509CertChainValidatorTest, NullSpiInput, TestSize.Level0)
{
    HcfCertChainValidatorSpi *spiObj = nullptr;
    CfResult res = HcfCertChainValidatorSpiCreate(nullptr);
    EXPECT_NE(res, CF_SUCCESS);
    res = HcfCertChainValidatorSpiCreate(&spiObj);
    EXPECT_EQ(res, CF_SUCCESS);
    res = spiObj->engineValidate(spiObj, nullptr);
    EXPECT_NE(res, CF_SUCCESS);
    CfArray data = { 0 };
    res = spiObj->engineValidate(nullptr, &data);
    EXPECT_NE(res, CF_SUCCESS);
    (void)spiObj->base.destroy(nullptr);
    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CertChainValidatorTest, InvalidSpiClass, TestSize.Level0)
{
    HcfCertChainValidatorSpi *spiObj = nullptr;
    CfResult res = HcfCertChainValidatorSpiCreate(&spiObj);
    EXPECT_EQ(res, CF_SUCCESS);
    HcfCertChainValidatorSpi invalidSpi;
    invalidSpi.base.getClass = GetInvalidValidatorClass;
    CfArray data = { 0 };
    data.count = 2; /* 2: count is valid */
    res = spiObj->engineValidate(&invalidSpi, &data);
    EXPECT_NE(res, CF_SUCCESS);
    (void)spiObj->base.destroy(&(invalidSpi.base));
    CfObjDestroy(spiObj);
}

HWTEST_F(CryptoX509CertChainValidatorTest, InvalidMalloc, TestSize.Level0)
{
    SetMockFlag(true);
    HcfCertChainValidator *pathValidator = nullptr;
    CfResult res = HcfCertChainValidatorCreate("PKIX", &pathValidator);
    EXPECT_EQ(res, CF_ERR_MALLOC);
    HcfCertChainData certsData = { 0 };
    certsData.dataLen = 1;
    res = g_validator->validate(g_validator, &certsData);
    EXPECT_NE(res, CF_SUCCESS);
    SetMockFlag(false);
}

HWTEST_F(CryptoX509CertChainValidatorTest, InvalidSpiMalloc, TestSize.Level0)
{
    HcfCertChainValidatorSpi *spiObj = nullptr;
    CfResult res = HcfCertChainValidatorSpiCreate(&spiObj);
    EXPECT_EQ(res, CF_SUCCESS);

    SetMockFlag(true);
    CfArray data = { nullptr, CF_FORMAT_PEM, 2 }; /* 2: count is valid */
    res = spiObj->engineValidate(spiObj, &data);
    EXPECT_NE(res, CF_SUCCESS);
    SetMockFlag(false);

    CfObjDestroy(spiObj);
}
}