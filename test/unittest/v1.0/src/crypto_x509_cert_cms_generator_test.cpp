/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cert_cms_generator.h"
#include "cf_blob.h"
#include "cf_mock.h"
#include "memory_mock.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "cf_memory.h"
#include "x509_cert_cms_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoX509CertCmsGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static char g_testRsaKeyPasswordPem[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: DES-EDE3-CBC,DB0AC6E3BEE16420\r\n\r\n"
"1N5xykdckthZnswMV7blxXm2RCqe/OByBfMwFI7JoXR8STtMiStd4xA3W405k1Ma\r\n"
"ExpsHgWwZaS23x+sQ1sL1dsqIPMrw1Vr+KrL20vQcCVjXPpGKauafVbtcWQ1r2PZ\r\n"
"QJ4KWP6FhUp+sGt2ItODW3dK+1GdqL22ZtANrgFzS42Wh8FSn0UMCf6RG62DK62J\r\n"
"z2jtf4XaorrGSjdTeY+fyyGfSyKidIMMBe+IXwlhCgAe7aHSaqXtMsv+BibB7PJ3\r\n"
"XmEp1D/0ptL3r46txyYcuy8jSNCkW8er93KKnlRN6KbuYZPvPNncWkzZBzV17t5d\r\n"
"QgtvVh32AKgqk5jm8YVnspOFiPrbrK9UN3IW15juFkfnhriM3IrKap4/kW+tfawZ\r\n"
"DmHkSyl8xqFK413Rv0UvYBTjOcGbs2BSJYEvp8CIjtA17SvLmNw70K2nXWuQYutY\r\n"
"+HyucPtHfEqUPQRzWTAMMntTru77u7dxo2WMMMxOtMJO5h7MAnZH9bAFiuO3ewcY\r\n"
"eEePg10d8Owcfh9G6kc0HIGT9MMLMi0mTXhpoQTuWPYuSx6uUZL1fsp1x2fuM0qn\r\n"
"bdf3+UnATYUu4tgvBHrMV7405Y6Y3PnqOFxVMeAHeOTo6UThtJ10mfeCPXGcUaHo\r\n"
"P5enw7h4145cha3+S4hNrUwj3skrtavld7tY74p4DvgZSlCMF3JAm3DhpnEMVcYP\r\n"
"Y6TkSevvxOpBvEHE41Y4VBCBwd9clcixI6cSBJKPUU4A/sc/kkNdGFcbzLQCg/zR\r\n"
"1m7YmBROb2qy4w3lv/uwVnPGLg/YV465irRaN3hgz7/1lm8STKQhmQ==\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

static char g_testRsaKeyPasswordPemError[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"Proc-Type: 4,ENCRYPTED\r\n"
"DEK-Info: DES-EDE3-CBC,DB0AC6E3BEE16420\r\n\r\n"
"1N5xykdckthZnswMV7blxXm2RCqe/OByBfMwFI7JoXR8STtMiStd4xA3W405k1Ma\r\n"
"ExpsHgWwZaS23x+sQ1sL1dsqIPMrw1Vr+KrL20vQcCVjXPpGKauafVbtcWQ1r2PZ\r\n"
"QJ4KWP6FhUp+sGt2ItODW3dK+1GdqL22ZtANrgFzS42Wh8FSn0UMCf6RG62DK62J\r\n"
"z2jtf4XaorrGSjdTeY+fyyGfSyKidIMMBe+IXwlhCgAe7aHSaqXtMsv+BibB7PJ3\r\n"
"XmEp1D/0ptL3r46txyYcuy8jSNCkW8er93KKnlRN6KbuYZPvPNncWkzZBzV17t5d\r\n"
"QgtvVh32AKgqk5jm8YVnspOFiPrbrK9UN3IW15juFkfnhriM3IrKap4/kW+tfawZ\r\n"
"DmHkSyl8xqFK413Rv0UvYBTjOcGbs2BSJYEvp8CIjtA17SvLmNw70K2nXWuQYutY\r\n"
"+HyucPtHfEqUPQRzWTAMMntTru77u7dxo2WMMMxOtMJO5h7MAnZH9bAFiuO3ewcY\r\n"
"eEePg10d8Owcfh9G6kc0HIGT9MMLMi0mTXhpoQTuWPYuSx6uUZL1fsp1x2fuM0qn\r\n"
"bdf3+UnATYUu4tgvBHrMV7405Y6Y3PnqOFxVMeAHeOTo6UThtJ10mfeCPXGcUaHo\r\n"
"P5enw7h4145cha3+S4hNrUwj3skrtavld7tY74p4DvgZSlCMF3JAm3DhpnEMVcYP\r\n"
"Y6TkSevvxOpBvEHE41Y4VBCBwd9clcixI6cSBJKPUU4A/sc/kkNdGFcbzLQCg/zR\r\n"
"1m7YmBROb2qy4w3lv/uwVnPGLg\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

static uint8_t g_testRsaKeyPasswordDer[] = {
0x30, 0x82, 0x02, 0xdd, 0x30, 0x57, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05,
0x0d, 0x30, 0x4a, 0x30, 0x29, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c,
0x30, 0x1c, 0x04, 0x08, 0x79, 0x08, 0x9d, 0xc0, 0xa8, 0x59, 0x4d, 0xc1, 0x02, 0x02, 0x08, 0x00,
0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09, 0x05, 0x00, 0x30, 0x1d,
0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02, 0x04, 0x10, 0x0e, 0xb7, 0x7d,
0x2b, 0x4b, 0x11, 0xc0, 0x40, 0x84, 0x62, 0xc9, 0xa9, 0x31, 0x29, 0x68, 0x2d, 0x04, 0x82, 0x02,
0x80, 0x78, 0xe4, 0xbd, 0x79, 0x77, 0x2e, 0xd7, 0x71, 0xce, 0xa0, 0x74, 0x0d, 0x2a, 0x8b, 0xcf,
0xa8, 0x37, 0x47, 0xbd, 0xe6, 0x4e, 0x47, 0xaa, 0x2c, 0xea, 0xcb, 0x2b, 0x5a, 0x1a, 0x9d, 0x4b,
0x38, 0x67, 0xec, 0xc1, 0xce, 0x10, 0x95, 0xb4, 0xba, 0x91, 0xa1, 0xa8, 0xa2, 0x17, 0x23, 0x33,
0x44, 0xc0, 0x3b, 0xc3, 0xa8, 0xc4, 0x7a, 0xcb, 0x9a, 0x8f, 0xa6, 0x07, 0x7e, 0x3e, 0xcc, 0xd8,
0xc7, 0x37, 0x4f, 0x14, 0xa8, 0xc0, 0x51, 0xe6, 0x6c, 0x7c, 0x01, 0x93, 0xcb, 0x0f, 0x65, 0x28,
0x4d, 0x94, 0xd1, 0xbd, 0xe3, 0x66, 0x6f, 0xf0, 0x82, 0x34, 0x82, 0x31, 0x30, 0xdb, 0x29, 0xa3,
0x9b, 0xca, 0xca, 0x43, 0xb6, 0xcd, 0x75, 0x0c, 0x6c, 0xd6, 0xd1, 0x7f, 0x2c, 0xff, 0x53, 0xb9,
0xa2, 0x79, 0x81, 0x35, 0xfd, 0x02, 0xe4, 0x2b, 0x1d, 0x83, 0x8c, 0xa3, 0x69, 0xf1, 0x64, 0x86,
0x41, 0x7d, 0xe0, 0x81, 0x50, 0x51, 0x85, 0xcd, 0x50, 0x23, 0xef, 0xeb, 0x8e, 0x1c, 0x38, 0x13,
0xd9, 0xb5, 0x7c, 0x40, 0x7d, 0x20, 0x69, 0x31, 0x74, 0x5f, 0x50, 0xb2, 0xb2, 0xbe, 0xce, 0xfc,
0x61, 0x37, 0x89, 0xc4, 0x2a, 0xed, 0x36, 0x57, 0xf6, 0x95, 0xc4, 0xc1, 0x9f, 0x76, 0x51, 0xe2,
0xef, 0x66, 0x90, 0x30, 0x40, 0x99, 0x73, 0xff, 0xe1, 0xaf, 0xaa, 0x95, 0x7f, 0x2f, 0x8f, 0x09,
0x16, 0x1b, 0x95, 0x5a, 0xdf, 0x02, 0x13, 0x5b, 0x1c, 0x27, 0x57, 0xb0, 0x7f, 0x88, 0xdd, 0x16,
0x3b, 0x35, 0x99, 0x5f, 0xdf, 0x03, 0xa0, 0x85, 0x45, 0x10, 0xc7, 0xa0, 0x4a, 0xe8, 0xa9, 0x57,
0xaf, 0x02, 0x16, 0x50, 0xac, 0xd8, 0x50, 0x5a, 0x68, 0x0d, 0x79, 0xe9, 0xee, 0x51, 0x24, 0x43,
0x63, 0xe3, 0x7c, 0x46, 0xe6, 0x8f, 0x0b, 0xfa, 0x84, 0xc5, 0xf6, 0xb5, 0x0a, 0x62, 0x8d, 0x6a,
0xf4, 0x25, 0xf9, 0x52, 0x12, 0x7f, 0x8b, 0xfb, 0x98, 0xe0, 0x57, 0x5a, 0x4e, 0x21, 0x1e, 0x99,
0x61, 0xc2, 0x8b, 0x32, 0xcd, 0xf4, 0x17, 0xa1, 0x70, 0xcc, 0xdf, 0xca, 0x1c, 0x3b, 0xbb, 0xca,
0xa1, 0xa1, 0x5c, 0x62, 0xc6, 0x24, 0xef, 0xb6, 0xcf, 0xba, 0xe9, 0xe7, 0x5a, 0x80, 0x30, 0x03,
0x08, 0x91, 0x7d, 0x80, 0x37, 0x86, 0xd5, 0x8f, 0x2c, 0x38, 0x3f, 0x1c, 0x7a, 0xef, 0xd9, 0x35,
0x78, 0x3f, 0xd5, 0xde, 0x9a, 0xd3, 0x00, 0x13, 0x56, 0x39, 0xe5, 0x45, 0x36, 0xe8, 0x5a, 0xb0,
0x08, 0x1b, 0xde, 0x95, 0x6d, 0x00, 0xb9, 0x90, 0x9f, 0xf0, 0x8a, 0x01, 0x91, 0xc5, 0x09, 0x40,
0xc1, 0xfd, 0x0c, 0xb3, 0xe4, 0xa5, 0xf5, 0xc4, 0xff, 0x27, 0xf4, 0x0a, 0xfc, 0x55, 0x3d, 0x1a,
0x69, 0x68, 0xc3, 0x63, 0xac, 0x68, 0x92, 0x5b, 0x88, 0xdf, 0xc3, 0x38, 0x22, 0x02, 0xa0, 0x6c,
0xb3, 0x93, 0xc7, 0x29, 0xdc, 0xbb, 0xf7, 0xac, 0x8d, 0xfe, 0x92, 0xfb, 0x28, 0x65, 0x2e, 0xbb,
0xbd, 0x0c, 0xa8, 0x80, 0x07, 0xf6, 0xac, 0xf5, 0x43, 0x03, 0x9a, 0xb9, 0xb9, 0x6d, 0xac, 0x5f,
0xc6, 0x48, 0x2c, 0x1a, 0xb9, 0xc8, 0x65, 0xd5, 0x43, 0x98, 0xf5, 0xeb, 0x15, 0xb7, 0xb7, 0xf4,
0x4b, 0xe8, 0xc8, 0x8e, 0x3d, 0x05, 0x9e, 0xda, 0x81, 0xdd, 0x41, 0x3d, 0x3b, 0xc1, 0xea, 0xc0,
0x03, 0x41, 0x46, 0xa8, 0x62, 0x05, 0x27, 0x99, 0xc5, 0x4f, 0xa3, 0x58, 0xff, 0x11, 0x4b, 0xfd,
0xe1, 0xae, 0x13, 0xc2, 0x28, 0xac, 0x9c, 0xe8, 0xb0, 0xbf, 0x77, 0x45, 0x03, 0x90, 0xca, 0xbf,
0xc2, 0xca, 0x9c, 0xdc, 0x00, 0x66, 0xd7, 0x56, 0x5b, 0x18, 0x2f, 0x88, 0x58, 0xc8, 0x2d, 0xf2,
0x85, 0x9b, 0x74, 0x2f, 0x79, 0x38, 0x2b, 0x0b, 0x2f, 0x1e, 0x8a, 0xa7, 0x57, 0xc3, 0x05, 0x94,
0x15, 0xc6, 0x60, 0x02, 0xe8, 0xf5, 0x6e, 0x1b, 0x3f, 0x42, 0x43, 0x44, 0xf1, 0xae, 0xad, 0xc6,
0xf3, 0xdd, 0xf8, 0xe0, 0x37, 0x65, 0xd8, 0x71, 0x0a, 0x87, 0x5e, 0x65, 0xb4, 0xe3, 0x11, 0x73,
0xab, 0xa3, 0x87, 0x8b, 0x9c, 0x6c, 0xc4, 0xea, 0xb2, 0xd6, 0x95, 0x7c, 0xd3, 0x82, 0xa7, 0xfd,
0x5d, 0x53, 0xe1, 0x22, 0x19, 0xfe, 0xfc, 0x02, 0x3e, 0x55, 0x8e, 0xb8, 0xd8, 0x4c, 0x79, 0xa8,
0xcd, 0x13, 0x74, 0xab, 0xca, 0xf2, 0x9b, 0xfe, 0xbc, 0xbe, 0x69, 0xff, 0x2d, 0x44, 0x62, 0x3a,
0xa0, 0x66, 0xbe, 0x7b, 0x22, 0xe7, 0x81, 0xc1, 0x58, 0xa5, 0x08, 0x0d, 0x1e, 0xdc, 0xb6, 0x77,
0xd1, 0xa3, 0xbc, 0x4b, 0x6a, 0x5d, 0x03, 0xd1, 0x05, 0x61, 0xd8, 0xac, 0xef, 0x2a, 0x9f, 0x3c,
0xc4, 0x9d, 0x80, 0xb3, 0x4a, 0x18, 0x23, 0x57, 0xa1, 0x5f, 0x7b, 0x28, 0x86, 0x09, 0x51, 0x71,
0xf4};

static uint8_t g_testRsaKeyPasswordDerError[] = {
0x30, 0x82, 0x02, 0xdd, 0x30, 0x57, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05,
0x0d, 0x30, 0x4a, 0x30, 0x29, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c,
0x30, 0x1c, 0x04, 0x08, 0x79, 0x08, 0x9d, 0xc0, 0xa8, 0x59, 0x4d, 0xc1, 0x02, 0x02, 0x08, 0x00,
0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09, 0x05, 0x00, 0x30, 0x1d,
0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02, 0x04, 0x10, 0x0e, 0xb7, 0x7d,
0x2b, 0x4b, 0x11, 0xc0, 0x40, 0x84, 0x62, 0xc9, 0xa9, 0x31, 0x29, 0x68, 0x2d, 0x04, 0x82, 0x02,
0x80, 0x78, 0xe4, 0xbd, 0x79, 0x77, 0x2e, 0xd7, 0x71, 0xce, 0xa0, 0x74, 0x0d, 0x2a, 0x8b, 0xcf,
0xa8, 0x37, 0x47, 0xbd, 0xe6, 0x4e, 0x47, 0xaa, 0x2c, 0xea, 0xcb, 0x2b, 0x5a, 0x1a, 0x9d, 0x4b,
0x38, 0x67, 0xec, 0xc1, 0xce, 0x10, 0x95, 0xb4, 0xba, 0x91, 0xa1, 0xa8, 0xa2, 0x17, 0x23, 0x33,
0x44, 0xc0, 0x3b, 0xc3, 0xa8, 0xc4, 0x7a, 0xcb, 0x9a, 0x8f, 0xa6, 0x07, 0x7e, 0x3e, 0xcc, 0xd8,
0xc7, 0x37, 0x4f, 0x14, 0xa8, 0xc0, 0x51, 0xe6, 0x6c, 0x7c, 0x01, 0x93, 0xcb, 0x0f, 0x65, 0x28,
0x4d, 0x94, 0xd1, 0xbd, 0xe3, 0x66, 0x6f, 0xf0, 0x82, 0x34, 0x82, 0x31, 0x30, 0xdb, 0x29, 0xa3,
0x9b, 0xca, 0xca, 0x43, 0xb6, 0xcd, 0x75, 0x0c, 0x6c, 0xd6, 0xd1, 0x7f, 0x2c, 0xff, 0x53, 0xb9,
0xa2, 0x79, 0x81, 0x35, 0xfd, 0x02, 0xe4, 0x2b, 0x1d, 0x83, 0x8c, 0xa3, 0x69, 0xf1, 0x64, 0x86,
0x41, 0x7d, 0xe0, 0x81, 0x50, 0x51, 0x85, 0xcd, 0x50, 0x23, 0xef, 0xeb, 0x8e, 0x1c, 0x38, 0x13,
0xd9, 0xb5, 0x7c, 0x40, 0x7d, 0x20, 0x69, 0x31, 0x74, 0x5f, 0x50, 0xb2, 0xb2, 0xbe, 0xce, 0xfc,
0x61, 0x37, 0x89, 0xc4, 0x2a, 0xed, 0x36, 0x57, 0xf6, 0x95, 0xc4, 0xc1, 0x9f, 0x76, 0x51, 0xe2,
0xef, 0x66, 0x90, 0x30, 0x40, 0x99, 0x73, 0xff, 0xe1, 0xaf, 0xaa, 0x95, 0x7f, 0x2f, 0x8f, 0x09,
0x16, 0x1b, 0x95, 0x5a, 0xdf, 0x02, 0x13, 0x5b, 0x1c, 0x27, 0x57, 0xb0, 0x7f, 0x88, 0xdd, 0x16,
0x3b, 0x35, 0x99, 0x5f, 0xdf, 0x03, 0xa0, 0x85, 0x45, 0x10, 0xc7, 0xa0, 0x4a, 0xe8, 0xa9, 0x57,
0xaf, 0x02, 0x16, 0x50, 0xac, 0xd8, 0x50, 0x5a, 0x68, 0x0d, 0x79, 0xe9, 0xee, 0x51, 0x24, 0x43,
0x63, 0xe3, 0x7c, 0x46, 0xe6, 0x8f, 0x0b, 0xfa, 0x84, 0xc5, 0xf6, 0xb5, 0x0a, 0x62, 0x8d, 0x6a,
0xf4, 0x25, 0xf9, 0x52, 0x12, 0x7f, 0x8b, 0xfb, 0x98, 0xe0, 0x57, 0x5a, 0x4e, 0x21, 0x1e, 0x99,
0x61, 0xc2, 0x8b, 0x32, 0xcd, 0xf4, 0x17, 0xa1, 0x70, 0xcc, 0xdf, 0xca, 0x1c, 0x3b, 0xbb, 0xca,
0xa1, 0xa1, 0x5c, 0x62, 0xc6, 0x24, 0xef, 0xb6, 0xcf, 0xba, 0xe9, 0xe7, 0x5a, 0x80, 0x30, 0x03,
0x08, 0x91, 0x7d, 0x80, 0x37, 0x86, 0xd5, 0x8f, 0x2c, 0x38, 0x3f, 0x1c, 0x7a, 0xef, 0xd9, 0x35,
0x78, 0x3f, 0xd5, 0xde, 0x9a, 0xd3, 0x00, 0x13, 0x56, 0x39, 0xe5, 0x45, 0x36, 0xe8, 0x5a, 0xb0,
0x08, 0x1b, 0xde, 0x95, 0x6d, 0x00, 0xb9, 0x90, 0x9f, 0xf0, 0x8a, 0x01, 0x91, 0xc5, 0x09, 0x40,
0xc1, 0xfd, 0x0c, 0xb3, 0xe4, 0xa5, 0xf5, 0xc4, 0xff, 0x27, 0xf4, 0x0a, 0xfc, 0x55, 0x3d, 0x1a,
0x69, 0x68, 0xc3, 0x63, 0xac, 0x68, 0x92, 0x5b, 0x88, 0xdf, 0xc3, 0x38, 0x22, 0x02, 0xa0, 0x6c,
0xb3, 0x93, 0xc7, 0x29, 0xdc, 0xbb, 0xf7, 0xac, 0x8d, 0xfe, 0x92, 0xfb, 0x28, 0x65, 0x2e, 0xbb,
0xbd, 0x0c, 0xa8, 0x80, 0x07, 0xf6, 0xac, 0xf5, 0x43, 0x03, 0x9a, 0xb9, 0xb9, 0x6d, 0xac, 0x5f,
0xc6, 0x48, 0x2c, 0x1a, 0xb9, 0xc8, 0x65, 0xd5, 0x43, 0x98, 0xf5, 0xeb, 0x15, 0xb7, 0xb7, 0xf4,
0x4b, 0xe8, 0xc8, 0x8e, 0x3d, 0x05, 0x9e, 0xda, 0x81, 0xdd, 0x41, 0x3d, 0x3b, 0xc1, 0xea, 0xc0,
0x03, 0x41, 0x46, 0xa8, 0x62, 0x05, 0x27, 0x99, 0xc5, 0x4f, 0xa3, 0x58, 0xff, 0x11, 0x4b, 0xfd,
0xe1, 0xae, 0x13, 0xc2, 0x28, 0xac, 0x9c, 0xe8, 0xb0, 0xbf, 0x77, 0x45, 0x03, 0x90, 0xca, 0xbf,
0xc2, 0xca, 0x9c, 0xdc, 0x00, 0x66, 0xd7, 0x56, 0x5b, 0x18, 0x2f, 0x88, 0x58, 0xc8, 0x2d, 0xf2,
0x85, 0x9b, 0x74, 0x2f, 0x79, 0x38, 0x2b, 0x0b, 0x2f, 0x1e, 0x8a, 0xa7, 0x57, 0xc3, 0x05, 0x94,
0x15, 0xc6, 0x60, 0x02, 0xe8, 0xf5, 0x6e, 0x1b, 0x3f, 0x42, 0x43, 0x44, 0xf1, 0xae, 0xad, 0xc6,
0xf3, 0xdd, 0xf8, 0xe0, 0x37, 0x65, 0xd8, 0x71, 0x0a, 0x87, 0x5e, 0x65, 0xb4, 0xe3, 0x11, 0x73,
0xab, 0xa3, 0x87, 0x8b, 0x9c, 0x6c, 0xc4, 0xea, 0xb2, 0xd6, 0x95, 0x7c, 0xd3, 0x82, 0xa7, 0xfd,
0x5d, 0x53, 0xe1, 0x22, 0x19, 0xfe, 0xfc, 0x02, 0x3e, 0x55, 0x8e, 0xb8, 0xd8, 0x4c, 0x79, 0xa8,
0xcd, 0x13, 0x74, 0xab, 0xca, 0xf2, 0x9b, 0xfe, 0xbc, 0xbe, 0x69, 0xff, 0x2d, 0x44, 0x62, 0x3a,
0xa0, 0x66, 0xbe, 0x7b, 0x22, 0xe7, 0x81, 0xc1, 0x58, 0xa5, 0x08, 0x0d, 0x1e, 0xdc, 0xb6, 0x77,
0xd1, 0xa3, 0xbc, 0x4b, 0x6a, 0x5d, 0x03, 0xd1, 0x05, 0x61, 0xd8, 0xac, 0xef, 0x2a, 0x9f, 0x3c,
0xc4, 0x9d, 0x80, 0xb3, 0x4a, 0x18, 0x23, 0x57, 0xa1, 0x5f, 0x7b, 0x28, 0x86, 0x09, 0x51, 0x71};

static char g_testRsaCertPasswordPem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICXjCCAcegAwIBAgIGAXKnJjrAMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYT\r\n"
"AkNOMQwwCgYDVQQIDANzaGExDTALBgNVBAcMBHhpYW4xDTALBgNVBAoMBHRlc3Qx\r\n"
"DTALBgNVBAMMBHRlc3QwHhcNMjQxMTIyMDkwNTIyWhcNMzQxMTIwMDkwNTIyWjBI\r\n"
"MQswCQYDVQQGEwJDTjEMMAoGA1UECAwDc2hhMQ0wCwYDVQQHDAR4aWFuMQ0wCwYD\r\n"
"VQQKDAR0ZXN0MQ0wCwYDVQQDDAR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\r\n"
"iQKBgQC6nCZTM16Rk2c4P/hwfVm++jqe6GCA/PXXGe4YL218q1dTKMHBGEw8kXi0\r\n"
"XLDcyyC2yUn8ywN2QSyly6ke9EE6PGfZywStLp4g2PTTWB04sS3aXT2y+fToiTXQ\r\n"
"3AxfFYRpB+EgSdSCkJs6jKXVwbzu54kEtQTfs8UdBQ9nVKaJLwIDAQABo1MwUTAd\r\n"
"BgNVHQ4EFgQU6QXnt1smb2HRSO/2zuRQnz/SDxowHwYDVR0jBBgwFoAU6QXnt1sm\r\n"
"b2HRSO/2zuRQnz/SDxowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOB\r\n"
"gQBPR/+5xzFG1XlTdgwWVvqVxvhGUkbMTGW0IviJ+jbKsi57vnVsOtFzEA6y+bYx\r\n"
"xG/kEOcwLtzeVHOQA+ZU5SVcc+qc0dfFiWjL2PSAG4bpqSTjujpuUk+g8ugixbG1\r\n"
"a26pkDJhNeB/E3eBIbeydSY0A/dIGb6vbGo6BSq2KvnWAA==\r\n"
"-----END CERTIFICATE-----\r\n";

static char g_testRsaCertPasswordPem2[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICXjCCAcegAwIBAgIGAXKnJjrAMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYT\r\n"
"AkNOMQwwCgYDVQQIDANzaGExDTALBgNVBAcMBHhpYW4xDTALBgNVBAoMBHRlc3Qx\r\n"
"DTALBgNVBAMMBHRlc3QwHhcNMjQxMjA5MTE1NzE1WhcNMzQxMjA3MTE1NzE1WjBI\r\n"
"MQswCQYDVQQGEwJDTjEMMAoGA1UECAwDc2hhMQ0wCwYDVQQHDAR4aWFuMQ0wCwYD\r\n"
"VQQKDAR0ZXN0MQ0wCwYDVQQDDAR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\r\n"
"iQKBgQDCmmNbA+i6gUOk1I7LahJtZMtPv8La7rE865y9lbsBht9LcGOrN/tupRV+\r\n"
"dM5miEsk6RsA88755+3RQeZia0ziRP2O3iKE965atdJZBKRarc7e88uFJQR6SfM8\r\n"
"2L0xJXuypnA+piEzVs7joFxeNxuCALnI9iLlqjmgwWKGIVJxMwIDAQABo1MwUTAd\r\n"
"BgNVHQ4EFgQUEYJQ9alCQmT3vq/iDn+joQPkuPcwHwYDVR0jBBgwFoAUEYJQ9alC\r\n"
"QmT3vq/iDn+joQPkuPcwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOB\r\n"
"gQBQdnW51Ag5uoZcbJgHU9tfIS60CYq8tyfVcbL/CtG2x5vQszF+dqWBhMEWnaV4\r\n"
"5+IOSPOxizE838wP1L84CxmRxkCCBbKCt4w79ZKRa/RcGB7NOQijM87ywogRo3Z4\r\n"
"7G3YE3NrPWlFAFGB6olmUz/JRdfbdbWW9ftTM0g+P9dq0Q==\r\n"
"-----END CERTIFICATE-----\r\n";

const CfEncodingBlob g_inCertPasswordPemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaCertPasswordPem),
    .len = strlen(g_testRsaCertPasswordPem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inCertPasswordPemStream2 = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaCertPasswordPem2),
    .len = strlen(g_testRsaCertPasswordPem2) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyPasswordPemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaKeyPasswordPem),
    .len = strlen(g_testRsaKeyPasswordPem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyPasswordPemStreamError = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaKeyPasswordPemError),
    .len = strlen(g_testRsaKeyPasswordPemError) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyPasswordDerStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaKeyPasswordDer),
    .len = sizeof(g_testRsaKeyPasswordDer),
    .encodingFormat = CF_FORMAT_DER
};

const CfEncodingBlob g_inKeyPasswordDerStreamError = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaKeyPasswordDerError),
    .len = sizeof(g_testRsaKeyPasswordDerError),
    .encodingFormat = CF_FORMAT_DER
};

static char g_testRsaKeyNoPasswordPem[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIICXAIBAAKBgQC+T3StG1Xv82Hlc6GtiVm9HiMAdfeAix+rTSYhzyB7x2SrksKs\r\n"
"YqcJItDrIGjaes/F9znT+Xacuj4aNgaKqPaopDpDgPD0PS+lIwGdjLtQy0ogqs59\r\n"
"D+/KRhtD/p1RVrUNpL/mti0s0hWCjbZcLr9qFoQ6figJaXz2TILTMppaxwIDAQAB\r\n"
"AoGAN3U8EP34SxZnns/Ve5ac+gmANbAq0eC499hhllSfqLJwWbdI16df+b+Vlg85\r\n"
"vwEu7weeaHE36XA0jLrVqS6XwgfyG6Y/cxh4mHJWmNeFYSLNkZaLfMzZEsvh/Gtp\r\n"
"dxobHekcOKGQKEvlFnU3POLP5yGAFHLVKy6Eu7vrPdjX8TECQQDyj9RkA85gFwye\r\n"
"8Kud5Q6Ddl0ForJN2WEpV4kaTPZPON7bYVlBYslWtsQwnvW8+B96dp5NFdHPM4Dw\r\n"
"mS1md3BzAkEAyNqP0Lhenpu068bNVkNxiuTj12WZ6FGp1+9l42dnjgl3aM0d4TIr\r\n"
"IOXNlk5bgXODiIUZUwQ/3TQdcXsd7YQ7XQJAEISo8xKrSDHpox1CoqMJpPw3g327\r\n"
"5L9L9ZPHe2oIUAbQbmInwOMoUOZrX+BDXdYL1rwjNZ6pxhF802WrCNJTbwJBAKSR\r\n"
"N56bQaORDobUh6+zaNeVvPziWV1Zc+DiXMgbFGTzaqwqy92U3nOA9pa9swn43H/C\r\n"
"FkLHy4/xwGIXryjJ3F0CQA3ieCRmYxrLiYQkxYyjBE4s8vV55Ldz0qNJTG4NvtgS\r\n"
"uvZuFdOpke8LnfL4lCVzTitVsvHh4UT9XGrqhPDHIxU=\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

static uint8_t g_testRsaKeyNoPasswordDer[] = {
0x30, 0x82, 0x02, 0x5C, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xBE, 0x4F, 0x74, 0xAD, 0x1B,
0x55, 0xEF, 0xF3, 0x61, 0xE5, 0x73, 0xA1, 0xAD, 0x89, 0x59, 0xBD, 0x1E, 0x23, 0x00, 0x75, 0xF7,
0x80, 0x8B, 0x1F, 0xAB, 0x4D, 0x26, 0x21, 0xCF, 0x20, 0x7B, 0xC7, 0x64, 0xAB, 0x92, 0xC2, 0xAC,
0x62, 0xA7, 0x09, 0x22, 0xD0, 0xEB, 0x20, 0x68, 0xDA, 0x7A, 0xCF, 0xC5, 0xF7, 0x39, 0xD3, 0xF9,
0x76, 0x9C, 0xBA, 0x3E, 0x1A, 0x36, 0x06, 0x8A, 0xA8, 0xF6, 0xA8, 0xA4, 0x3A, 0x43, 0x80, 0xF0,
0xF4, 0x3D, 0x2F, 0xA5, 0x23, 0x01, 0x9D, 0x8C, 0xBB, 0x50, 0xCB, 0x4A, 0x20, 0xAA, 0xCE, 0x7D,
0x0F, 0xEF, 0xCA, 0x46, 0x1B, 0x43, 0xFE, 0x9D, 0x51, 0x56, 0xB5, 0x0D, 0xA4, 0xBF, 0xE6, 0xB6,
0x2D, 0x2C, 0xD2, 0x15, 0x82, 0x8D, 0xB6, 0x5C, 0x2E, 0xBF, 0x6A, 0x16, 0x84, 0x3A, 0x7E, 0x28,
0x09, 0x69, 0x7C, 0xF6, 0x4C, 0x82, 0xD3, 0x32, 0x9A, 0x5A, 0xC7, 0x02, 0x03, 0x01, 0x00, 0x01,
0x02, 0x81, 0x80, 0x37, 0x75, 0x3C, 0x10, 0xFD, 0xF8, 0x4B, 0x16, 0x67, 0x9E, 0xCF, 0xD5, 0x7B,
0x96, 0x9C, 0xFA, 0x09, 0x80, 0x35, 0xB0, 0x2A, 0xD1, 0xE0, 0xB8, 0xF7, 0xD8, 0x61, 0x96, 0x54,
0x9F, 0xA8, 0xB2, 0x70, 0x59, 0xB7, 0x48, 0xD7, 0xA7, 0x5F, 0xF9, 0xBF, 0x95, 0x96, 0x0F, 0x39,
0xBF, 0x01, 0x2E, 0xEF, 0x07, 0x9E, 0x68, 0x71, 0x37, 0xE9, 0x70, 0x34, 0x8C, 0xBA, 0xD5, 0xA9,
0x2E, 0x97, 0xC2, 0x07, 0xF2, 0x1B, 0xA6, 0x3F, 0x73, 0x18, 0x78, 0x98, 0x72, 0x56, 0x98, 0xD7,
0x85, 0x61, 0x22, 0xCD, 0x91, 0x96, 0x8B, 0x7C, 0xCC, 0xD9, 0x12, 0xCB, 0xE1, 0xFC, 0x6B, 0x69,
0x77, 0x1A, 0x1B, 0x1D, 0xE9, 0x1C, 0x38, 0xA1, 0x90, 0x28, 0x4B, 0xE5, 0x16, 0x75, 0x37, 0x3C,
0xE2, 0xCF, 0xE7, 0x21, 0x80, 0x14, 0x72, 0xD5, 0x2B, 0x2E, 0x84, 0xBB, 0xBB, 0xEB, 0x3D, 0xD8,
0xD7, 0xF1, 0x31, 0x02, 0x41, 0x00, 0xF2, 0x8F, 0xD4, 0x64, 0x03, 0xCE, 0x60, 0x17, 0x0C, 0x9E,
0xF0, 0xAB, 0x9D, 0xE5, 0x0E, 0x83, 0x76, 0x5D, 0x05, 0xA2, 0xB2, 0x4D, 0xD9, 0x61, 0x29, 0x57,
0x89, 0x1A, 0x4C, 0xF6, 0x4F, 0x38, 0xDE, 0xDB, 0x61, 0x59, 0x41, 0x62, 0xC9, 0x56, 0xB6, 0xC4,
0x30, 0x9E, 0xF5, 0xBC, 0xF8, 0x1F, 0x7A, 0x76, 0x9E, 0x4D, 0x15, 0xD1, 0xCF, 0x33, 0x80, 0xF0,
0x99, 0x2D, 0x66, 0x77, 0x70, 0x73, 0x02, 0x41, 0x00, 0xC8, 0xDA, 0x8F, 0xD0, 0xB8, 0x5E, 0x9E,
0x9B, 0xB4, 0xEB, 0xC6, 0xCD, 0x56, 0x43, 0x71, 0x8A, 0xE4, 0xE3, 0xD7, 0x65, 0x99, 0xE8, 0x51,
0xA9, 0xD7, 0xEF, 0x65, 0xE3, 0x67, 0x67, 0x8E, 0x09, 0x77, 0x68, 0xCD, 0x1D, 0xE1, 0x32, 0x2B,
0x20, 0xE5, 0xCD, 0x96, 0x4E, 0x5B, 0x81, 0x73, 0x83, 0x88, 0x85, 0x19, 0x53, 0x04, 0x3F, 0xDD,
0x34, 0x1D, 0x71, 0x7B, 0x1D, 0xED, 0x84, 0x3B, 0x5D, 0x02, 0x40, 0x10, 0x84, 0xA8, 0xF3, 0x12,
0xAB, 0x48, 0x31, 0xE9, 0xA3, 0x1D, 0x42, 0xA2, 0xA3, 0x09, 0xA4, 0xFC, 0x37, 0x83, 0x7D, 0xBB,
0xE4, 0xBF, 0x4B, 0xF5, 0x93, 0xC7, 0x7B, 0x6A, 0x08, 0x50, 0x06, 0xD0, 0x6E, 0x62, 0x27, 0xC0,
0xE3, 0x28, 0x50, 0xE6, 0x6B, 0x5F, 0xE0, 0x43, 0x5D, 0xD6, 0x0B, 0xD6, 0xBC, 0x23, 0x35, 0x9E,
0xA9, 0xC6, 0x11, 0x7C, 0xD3, 0x65, 0xAB, 0x08, 0xD2, 0x53, 0x6F, 0x02, 0x41, 0x00, 0xA4, 0x91,
0x37, 0x9E, 0x9B, 0x41, 0xA3, 0x91, 0x0E, 0x86, 0xD4, 0x87, 0xAF, 0xB3, 0x68, 0xD7, 0x95, 0xBC,
0xFC, 0xE2, 0x59, 0x5D, 0x59, 0x73, 0xE0, 0xE2, 0x5C, 0xC8, 0x1B, 0x14, 0x64, 0xF3, 0x6A, 0xAC,
0x2A, 0xCB, 0xDD, 0x94, 0xDE, 0x73, 0x80, 0xF6, 0x96, 0xBD, 0xB3, 0x09, 0xF8, 0xDC, 0x7F, 0xC2,
0x16, 0x42, 0xC7, 0xCB, 0x8F, 0xF1, 0xC0, 0x62, 0x17, 0xAF, 0x28, 0xC9, 0xDC, 0x5D, 0x02, 0x40,
0x0D, 0xE2, 0x78, 0x24, 0x66, 0x63, 0x1A, 0xCB, 0x89, 0x84, 0x24, 0xC5, 0x8C, 0xA3, 0x04, 0x4E,
0x2C, 0xF2, 0xF5, 0x79, 0xE4, 0xB7, 0x73, 0xD2, 0xA3, 0x49, 0x4C, 0x6E, 0x0D, 0xBE, 0xD8, 0x12,
0xBA, 0xF6, 0x6E, 0x15, 0xD3, 0xA9, 0x91, 0xEF, 0x0B, 0x9D, 0xF2, 0xF8, 0x94, 0x25, 0x73, 0x4E,
0x2B, 0x55, 0xB2, 0xF1, 0xE1, 0xE1, 0x44, 0xFD, 0x5C, 0x6A, 0xEA, 0x84, 0xF0, 0xC7, 0x23, 0x15
};

static char g_testRsaCertNoPasswordPem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICXjCCAcegAwIBAgIGAXKnJjrAMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYT\r\n"
"AkNOMQwwCgYDVQQIDANzaGExDTALBgNVBAcMBHhpYW4xDTALBgNVBAoMBHRlc3Qx\r\n"
"DTALBgNVBAMMBHRlc3QwHhcNMjQxMTIzMDY0NTE0WhcNMzQxMTIxMDY0NTE0WjBI\r\n"
"MQswCQYDVQQGEwJDTjEMMAoGA1UECAwDc2hhMQ0wCwYDVQQHDAR4aWFuMQ0wCwYD\r\n"
"VQQKDAR0ZXN0MQ0wCwYDVQQDDAR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\r\n"
"iQKBgQC+T3StG1Xv82Hlc6GtiVm9HiMAdfeAix+rTSYhzyB7x2SrksKsYqcJItDr\r\n"
"IGjaes/F9znT+Xacuj4aNgaKqPaopDpDgPD0PS+lIwGdjLtQy0ogqs59D+/KRhtD\r\n"
"/p1RVrUNpL/mti0s0hWCjbZcLr9qFoQ6figJaXz2TILTMppaxwIDAQABo1MwUTAd\r\n"
"BgNVHQ4EFgQURGOFkFgbK+2zdxL1khm8NAK0AdQwHwYDVR0jBBgwFoAURGOFkFgb\r\n"
"K+2zdxL1khm8NAK0AdQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOB\r\n"
"gQBXVFVq7FfRftZ/qAGh5MrBctO8kzLQkpz7DYi6JRy2WDbYSdVHVZ+yWILt9I9o\r\n"
"64MtVN/+ZQMtDKxBp8JC2WCSUBP7R3rK7fyAdgWu621ISNAtcvLYJRYhH8o6PIC8\r\n"
"ajM5uoFMMM6z35VMJwlfhq/7d7E8Kz5wghbYnAg2ZrYBKA==\r\n"
"-----END CERTIFICATE-----\r\n";

const CfEncodingBlob g_inCertNoPasswordPemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaCertNoPasswordPem),
    .len = strlen(g_testRsaCertNoPasswordPem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyNoPasswordPemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaKeyNoPasswordPem),
    .len = strlen(g_testRsaKeyNoPasswordPem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyNoPasswordDerStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaKeyNoPasswordDer),
    .len = sizeof(g_testRsaKeyNoPasswordDer),
    .encodingFormat = CF_FORMAT_DER
};

static char g_testEccKeyPem[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIODRxm2YjHqVMx8ilrOH/dT7RsPWzjsJKuFr0+xYBWkCoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEc4Neg+rbDR2Wu8NLSxxaa14OZFEIF7/779yiDNtYWPlg2DM9Tkk+\r\n"
"LZk3kFkBfJAEbY42xwcbTj7n1sTH8X+dVg==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

static char g_testEccCertPem[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICOjCCAd+gAwIBAgIGAXKnJjrAMAoGCCqGSM49BAMCMHkxCzAJBgNVBAYTAmNo\r\n"
"MQ8wDQYDVQQIDAZodWF3ZWkxDTALBgNVBAcMBHhpYW4xDzANBgNVBAoMBmh1YXdl\r\n"
"aTENMAsGA1UECwwEdGVzdDENMAsGA1UEAwwEYW5uZTEbMBkGCSqGSIb3DQEJARYM\r\n"
"dGVzdEAxMjMuY29tMB4XDTI0MTEyNzAzMjQ1MFoXDTM0MTEyNTAzMjQ1MFoweTEL\r\n"
"MAkGA1UEBhMCY2gxDzANBgNVBAgMBmh1YXdlaTENMAsGA1UEBwwEeGlhbjEPMA0G\r\n"
"A1UECgwGaHVhd2VpMQ0wCwYDVQQLDAR0ZXN0MQ0wCwYDVQQDDARhbm5lMRswGQYJ\r\n"
"KoZIhvcNAQkBFgx0ZXN0QDEyMy5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\r\n"
"AARzg16D6tsNHZa7w0tLHFprXg5kUQgXv/vv3KIM21hY+WDYMz1OST4tmTeQWQF8\r\n"
"kARtjjbHBxtOPufWxMfxf51Wo1MwUTAdBgNVHQ4EFgQUU/P31GCBwyrj3yXkoNaX\r\n"
"xvPp8uIwHwYDVR0jBBgwFoAUU/P31GCBwyrj3yXkoNaXxvPp8uIwDwYDVR0TAQH/\r\n"
"BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEA/wCfbTorAWEEZcgd0CgfXI+EzXu2\r\n"
"Y88BmDD5LFlj3N0CIQDB34h77Li0CSpYpS4+7Mug237zbkFjHR3Q4/VWOT1G1A==\r\n"
"-----END CERTIFICATE-----\r\n";

const CfEncodingBlob g_inCertEccPemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testEccCertPem),
    .len = strlen(g_testEccCertPem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyEccPemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testEccKeyPem),
    .len = strlen(g_testEccKeyPem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

static char g_testleftPem[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICejCCAiCgAwIBAgIUGE371/LcCW79mzMm6UiJdyC4khcwCgYIKoZIzj0EAwIw\r\n"
    "fjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
    "bmcxHjAcBgNVBAoMFUVDRFNBIEludGVybWVkaWF0ZSBDQTELMAkGA1UECwwCSVQx\r\n"
    "HjAcBgNVBAMMFUVDRFNBIEludGVybWVkaWF0ZSBDQTAeFw0yNTA5MjgxMDU0MDVa\r\n"
    "Fw0zNTA5MjYxMDU0MDVaMHUxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5n\r\n"
    "MRAwDgYDVQQHDAdCZWlqaW5nMRswGQYDVQQKDBJFQ0RTQSBFeGFtcGxlIENvcnAx\r\n"
    "CzAJBgNVBAsMAklUMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcqhkjO\r\n"
    "PQIBBggqhkjOPQMBBwNCAAQNKO5YXAsmdm/ShEU5VyQlQSdnV6hNQIofHhQ/GyeK\r\n"
    "1W7t3KnMie4cv/wnA4Qmor2KeBBXUFUnYJqqWOHsivIuo4GEMIGBMAkGA1UdEwQC\r\n"
    "MAAwCwYDVR0PBAQDAgK0MCcGA1UdEQQgMB6CD3d3dy5leGFtcGxlLmNvbYILZXhh\r\n"
    "bXBsZS5jb20wHQYDVR0OBBYEFD7RUSUimy0SWShmPIus91tDS0u9MB8GA1UdIwQY\r\n"
    "MBaAFFjgVG0DwmSwxzJWELNvxGtm3mxUMAoGCCqGSM49BAMCA0gAMEUCIQCTw7sx\r\n"
    "X0tt1xiNvIQ9LD4bECzdgzIuBaU97GgYDusIUgIgTkc0wYZ3EUg0COHPly4cVsTj\r\n"
    "1Cyy/+qufhBUJw5om7E=\r\n"
    "-----END CERTIFICATE-----\r\n";

static char g_interPem[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICTDCCAfGgAwIBAgIUc1x0keEiLIcS1oKtSpeEiPoaepkwCgYIKoZIzj0EAwIw\r\n"
    "bjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
    "bmcxFjAUBgNVBAoMDUVDRFNBIFJvb3QgQ0ExCzAJBgNVBAsMAklUMRYwFAYDVQQD\r\n"
    "DA1FQ0RTQSBSb290IENBMB4XDTI1MDkyODEwNTM0OVoXDTMwMDkyNzEwNTM0OVow\r\n"
    "fjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
    "bmcxHjAcBgNVBAoMFUVDRFNBIEludGVybWVkaWF0ZSBDQTELMAkGA1UECwwCSVQx\r\n"
    "HjAcBgNVBAMMFUVDRFNBIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqG\r\n"
    "SM49AwEHA0IABGoCqpHBV/glJeezsp693/hhflYOKpHvaNszVBLkTurkqrbhbaMo\r\n"
    "hw1oO2Zro54rhZ8tom2UAGn1rzNmRVBCxTajXTBbMAwGA1UdEwQFMAMBAf8wCwYD\r\n"
    "VR0PBAQDAgEGMB0GA1UdDgQWBBRY4FRtA8JksMcyVhCzb8RrZt5sVDAfBgNVHSME\r\n"
    "GDAWgBTmNm24RfPnLf1HMNCocS90CGalJjAKBggqhkjOPQQDAgNJADBGAiEAstMv\r\n"
    "puHi/dgAlvycicL3VQ5iITvUSG2fo286LYc01CQCIQCyw4+94ovyRtaT/WWoZh3u\r\n"
    "ia4tt478nYeQgMChg+xtSw==\r\n"
    "-----END CERTIFICATE-----\r\n";

static char g_verifyRootPem[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICUzCCAfqgAwIBAgIUPma0DkC+ck+t/3eykmsKsy5D0egwCgYIKoZIzj0EAwIw\r\n"
    "bjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
    "bmcxFjAUBgNVBAoMDUVDRFNBIFJvb3QgQ0ExCzAJBgNVBAsMAklUMRYwFAYDVQQD\r\n"
    "DA1FQ0RTQSBSb290IENBMB4XDTI1MDkyODEwNTMyN1oXDTM1MDkyNjEwNTMyN1ow\r\n"
    "bjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
    "bmcxFjAUBgNVBAoMDUVDRFNBIFJvb3QgQ0ExCzAJBgNVBAsMAklUMRYwFAYDVQQD\r\n"
    "DA1FQ0RTQSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEA3KYWepl\r\n"
    "wjHe/Htx2cAhrjaZpWPJOUyL6siUFRayVebaqOQejuUPypbj+u4ZHodsviUe12E1\r\n"
    "50Q+R9Uayes+WKN2MHQwHQYDVR0OBBYEFOY2bbhF8+ct/Ucw0KhxL3QIZqUmMB8G\r\n"
    "A1UdIwQYMBaAFOY2bbhF8+ct/Ucw0KhxL3QIZqUmMAsGA1UdDwQEAwIBBjAJBgNV\r\n"
    "HREEAjAAMAkGA1UdEgQCMAAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNH\r\n"
    "ADBEAiAjo+sFDtGVhyc+NqdwxhepqSXOjRI5As6TSz3OYTvERwIgayLgfBn2uABH\r\n"
    "wYQI60CEJkDF9Pn2fxsGuNEyyn0ks28=\r\n"
    "-----END CERTIFICATE-----\r\n";

static char g_signedCmsPem[] =
    "-----BEGIN CMS-----\r\n"
    "MIIEpQYJKoZIhvcNAQcCoIIEljCCBJICAQExDTALBglghkgBZQMEAgQwEwYJKoZI\r\n"
    "hvcNAQcBoAYEBAECAwSgggJ+MIICejCCAiCgAwIBAgIUGE371/LcCW79mzMm6UiJ\r\n"
    "dyC4khcwCgYIKoZIzj0EAwIwfjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWpp\r\n"
    "bmcxEDAOBgNVBAcMB0JlaWppbmcxHjAcBgNVBAoMFUVDRFNBIEludGVybWVkaWF0\r\n"
    "ZSBDQTELMAkGA1UECwwCSVQxHjAcBgNVBAMMFUVDRFNBIEludGVybWVkaWF0ZSBD\r\n"
    "QTAeFw0yNTA5MjgxMDU0MDVaFw0zNTA5MjYxMDU0MDVaMHUxCzAJBgNVBAYTAkNO\r\n"
    "MRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMRswGQYDVQQKDBJF\r\n"
    "Q0RTQSBFeGFtcGxlIENvcnAxCzAJBgNVBAsMAklUMRgwFgYDVQQDDA93d3cuZXhh\r\n"
    "bXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQNKO5YXAsmdm/ShEU5\r\n"
    "VyQlQSdnV6hNQIofHhQ/GyeK1W7t3KnMie4cv/wnA4Qmor2KeBBXUFUnYJqqWOHs\r\n"
    "ivIuo4GEMIGBMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgK0MCcGA1UdEQQgMB6CD3d3\r\n"
    "dy5leGFtcGxlLmNvbYILZXhhbXBsZS5jb20wHQYDVR0OBBYEFD7RUSUimy0SWShm\r\n"
    "PIus91tDS0u9MB8GA1UdIwQYMBaAFFjgVG0DwmSwxzJWELNvxGtm3mxUMAoGCCqG\r\n"
    "SM49BAMCA0gAMEUCIQCTw7sxX0tt1xiNvIQ9LD4bECzdgzIuBaU97GgYDusIUgIg\r\n"
    "Tkc0wYZ3EUg0COHPly4cVsTj1Cyy/+qufhBUJw5om7ExggHlMIIB4QIBATCBljB+\r\n"
    "MQswCQYDVQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamlu\r\n"
    "ZzEeMBwGA1UECgwVRUNEU0EgSW50ZXJtZWRpYXRlIENBMQswCQYDVQQLDAJJVDEe\r\n"
    "MBwGA1UEAwwVRUNEU0EgSW50ZXJtZWRpYXRlIENBAhQYTfvX8twJbv2bMybpSIl3\r\n"
    "ILiSFzALBglghkgBZQMEAgSggeAwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc\r\n"
    "BgkqhkiG9w0BCQUxDxcNMjUwOTI5MDM1NzM1WjArBgkqhkiG9w0BCQQxHgQc/hln\r\n"
    "L6IKzcanlPftaN11Y8J/ZHkgFkuZHxrQNzB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCG\r\n"
    "SAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA4G\r\n"
    "CCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0D\r\n"
    "AgIBKDAKBggqhkjOPQQDAQRHMEUCIAn+mv09rGWttN80CgEdVM5hstWDWZhDXX/x\r\n"
    "NcqMlVCnAiEA7ZPsEoe6fvK+YPzyONcWKAeSwEbM2GH1NOXjjsA3+0M=\r\n"
    "-----END CMS-----\r\n";

static char g_emmptyDataCms[] =
    "-----BEGIN CMS-----\r\n"
    "MIICHgYJKoZIhvcNAQcCoIICDzCCAgsCAQExDTALBglghkgBZQMEAgEwCwYJKoZI\r\n"
    "hvcNAQcBMYIB6DCCAeQCAQEwgZYwfjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0Jl\r\n"
    "aWppbmcxEDAOBgNVBAcMB0JlaWppbmcxHjAcBgNVBAoMFUVDRFNBIEludGVybWVk\r\n"
    "aWF0ZSBDQTELMAkGA1UECwwCSVQxHjAcBgNVBAMMFUVDRFNBIEludGVybWVkaWF0\r\n"
    "ZSBDQQIUGE371/LcCW79mzMm6UiJdyC4khcwCwYJYIZIAWUDBAIBoIHkMBgGCSqG\r\n"
    "SIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MTAxMDA4MjU1\r\n"
    "MVowLwYJKoZIhvcNAQkEMSIEIOOwxEKY/BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4\r\n"
    "UrhVMHkGCSqGSIb3DQEJDzFsMGowCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjAL\r\n"
    "BglghkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3\r\n"
    "DQMCAgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMAoGCCqGSM49BAMCBEYwRAIg\r\n"
    "TnMwlwpykrJXu5FWwOOfXQHyJS+uvwMqv+3rNNQfFhYCIGnjny8I3suORTF2+FnP\r\n"
    "WoF6o9ydpYm4wwbJcQdoE2Wa\r\n"
    "-----END CMS-----\r\n";

static char g_emptyMiddleCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICTDCCAfGgAwIBAgIUc1x0keEiLIcS1oKtSpeEiPoaepkwCgYIKoZIzj0EAwIw\r\n"
    "bjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
    "bmcxFjAUBgNVBAoMDUVDRFNBIFJvb3QgQ0ExCzAJBgNVBAsMAklUMRYwFAYDVQQD\r\n"
    "DA1FQ0RTQSBSb290IENBMB4XDTI1MDkyODEwNTM0OVoXDTMwMDkyNzEwNTM0OVow\r\n"
    "fjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
    "bmcxHjAcBgNVBAoMFUVDRFNBIEludGVybWVkaWF0ZSBDQTELMAkGA1UECwwCSVQx\r\n"
    "HjAcBgNVBAMMFUVDRFNBIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqG\r\n"
    "SM49AwEHA0IABGoCqpHBV/glJeezsp693/hhflYOKpHvaNszVBLkTurkqrbhbaMo\r\n"
    "hw1oO2Zro54rhZ8tom2UAGn1rzNmRVBCxTajXTBbMAwGA1UdEwQFMAMBAf8wCwYD\r\n"
    "VR0PBAQDAgEGMB0GA1UdDgQWBBRY4FRtA8JksMcyVhCzb8RrZt5sVDAfBgNVHSME\r\n"
    "GDAWgBTmNm24RfPnLf1HMNCocS90CGalJjAKBggqhkjOPQQDAgNJADBGAiEAstMv\r\n"
    "puHi/dgAlvycicL3VQ5iITvUSG2fo286LYc01CQCIQCyw4+94ovyRtaT/WWoZh3u\r\n"
    "ia4tt478nYeQgMChg+xtSw==\r\n"
    "-----END CERTIFICATE-----\r\n";

static char g_emptyRootCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICUzCCAfqgAwIBAgIUPma0DkC+ck+t/3eykmsKsy5D0egwCgYIKoZIzj0EAwIw\r\n"
    "bjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
    "bmcxFjAUBgNVBAoMDUVDRFNBIFJvb3QgQ0ExCzAJBgNVBAsMAklUMRYwFAYDVQQD\r\n"
    "DA1FQ0RTQSBSb290IENBMB4XDTI1MDkyODEwNTMyN1oXDTM1MDkyNjEwNTMyN1ow\r\n"
    "bjELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWpp\r\n"
    "bmcxFjAUBgNVBAoMDUVDRFNBIFJvb3QgQ0ExCzAJBgNVBAsMAklUMRYwFAYDVQQD\r\n"
    "DA1FQ0RTQSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEA3KYWepl\r\n"
    "wjHe/Htx2cAhrjaZpWPJOUyL6siUFRayVebaqOQejuUPypbj+u4ZHodsviUe12E1\r\n"
    "50Q+R9Uayes+WKN2MHQwHQYDVR0OBBYEFOY2bbhF8+ct/Ucw0KhxL3QIZqUmMB8G\r\n"
    "A1UdIwQYMBaAFOY2bbhF8+ct/Ucw0KhxL3QIZqUmMAsGA1UdDwQEAwIBBjAJBgNV\r\n"
    "HREEAjAAMAkGA1UdEgQCMAAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNH\r\n"
    "ADBEAiAjo+sFDtGVhyc+NqdwxhepqSXOjRI5As6TSz3OYTvERwIgayLgfBn2uABH\r\n"
    "wYQI60CEJkDF9Pn2fxsGuNEyyn0ks28=\r\n"
    "-----END CERTIFICATE-----\r\n";

static char g_encryptedCmsPem[] =
    "-----BEGIN CMS-----\r\n"
    "MIIEXQYJKoZIhvcNAQcDoIIETjCCBEoCAQIxggQFMIHpAgEAMFIwSDELMAkGA1UE\r\n"
    "BhMCQ04xCzAJBgNVBAgMAlNYMQ4wDAYDVQQHDAV4aSBhbjENMAsGA1UECgwEVGVz\r\n"
    "dDENMAsGA1UEAwwEdGVzdAIGAXKnJjrEMA0GCSqGSIb3DQEBAQUABIGAmj9WNBIB\r\n"
    "uQ9cl7a8YGvKw0sRcRDZtj0ivupGTcHKShj54g3Jxb+WiYvR7YwKjtH/S16z28DQ\r\n"
    "jdAb4Oh7zRkHRsXwiTcTyu9269tib8LwLyvjhNZ1yIy+IjkNGhXD0xGnyb6BjSHx\r\n"
    "gZGuWgAWoyvsPWyuwTo69iiWcq142yjuZ2ChggEDAgEDoFGhTzAJBgcqhkjOPQIB\r\n"
    "A0IABMpGxKtyYoyJNWI/UMjNRnKHBEHtKnZErzYbbh4e6iUtEyCyOg3RGMHCcTKA\r\n"
    "HZGNd28hVI0nNhDs7iIkvA79vyMwGAYJK4EFEIZIPwACMAsGCWCGSAFlAwQBLTCB\r\n"
    "kDCBjTBhMFcxCzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAbpmZXopb8xDzANBgNVBAcM\r\n"
    "Builv+WuiTEPMA0GA1UECgwG5rWL6K+VMRUwEwYDVQQDDAzkuK3mlofmtYvor5UC\r\n"
    "BgFypyY6wAQonc7hNmlgIo6UA/WjKRvjBHy8xEFjOG7yOJ+BWFL/jbtQc2USKFGa\r\n"
    "16GCAb4CAQOgggEYoYIBFDAJBgcqhkjOPgIBA4IBBQACggEAN7IzujspteV8tf8T\r\n"
    "K9zfBa8mKd9mulZt+pylXQhKiKSUXdzP/SLLhwUm7YL8J0kkIeaGQQpzu68bG5Ua\r\n"
    "NNhhsr07FNbM9D0zi6tzJ/5QI7pVFRex7CxSgsJkx4tIuNYm3xPiQsGnT2PmOgE3\r\n"
    "1GYJTQtE7g+Ne5aqUvQ73iTEsTFDtvX4yu++KQg3KQJIrG8dyzkazKafs2mHYyQO\r\n"
    "HVZrfRc7lzV6ef5W0y+9/MdjB2/ERnmS3CBVlf+UkWxUIqUKeZAn6JHt8j2tAzGZ\r\n"
    "9I71ogpP8zo915pXXnftOPmXGj4AJKaMGn7vAUODW0UZpe01xtKuaB7GvjEsFEjK\r\n"
    "7NIiFjAaBgsqhkiG9w0BCRADBTALBglghkgBZQMEAS0wgYAwfjBSMEgxCzAJBgNV\r\n"
    "BAYTAkNOMQswCQYDVQQIDAJTWDEOMAwGA1UEBwwFeGkgYW4xDTALBgNVBAoMBFRl\r\n"
    "c3QxDTALBgNVBAMMBHRlc3QCBgFypyY6xQQoIr8kwhfnKxAkUS89Vgvwr+cirYKu\r\n"
    "ASIOwxaLnE8sY8DbWcKZeASbBaJOAgEEMBIEEDEyMzQ1Njc4OTBhYmNkZWYwCwYJ\r\n"
    "YIZIAWUDBAEtBCh4myONQEamB1ODZIANFV+erQSc87dKLFJCGzhrnFr/oGU2hvNJ\r\n"
    "SiZaMDwGCSqGSIb3DQEHATAdBglghkgBZQMEASoEEJN4M6Q1ywSjw9o3tZr2YrmA\r\n"
    "EAcdXtfS+2vx5JYg2sSklG8=\r\n"
    "-----END CMS-----\r\n";

static char g_privateKey[] =
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "MHcCAQEEIDmMBMiMN2TSAC+MTqT+nlXEGHKy9rH57erwdM/bSpjJoAoGCCqGSM49\r\n"
    "AwEHoUQDQgAEB06h4SzOryi3d7PW9yN2wACCVxlduBQjVLWZlDKhFKkdZjve8mUy\r\n"
    "ytSSbBj/rrzR2XmzUzofuNkUbAtje3DDJg==\r\n"
    "-----END EC PRIVATE KEY-----\r\n";

static char g_pubKey[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICGDCCAb6gAwIBAgIGAXKnJjrAMAoGCCqGSM49BAMCMFcxCzAJBgNVBAYTAkNO\r\n"
    "MQ8wDQYDVQQIDAbpmZXopb8xDzANBgNVBAcMBuilv+WuiTEPMA0GA1UECgwG5rWL\r\n"
    "6K+VMRUwEwYDVQQDDAzkuK3mlofmtYvor5UwHhcNMjUwOTE2MDY0MTMwWhcNMzUw\r\n"
    "OTE0MDY0MTMwWjBXMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG6ZmV6KW/MQ8wDQYD\r\n"
    "VQQHDAbopb/lrokxDzANBgNVBAoMBua1i+ivlTEVMBMGA1UEAwwM5Lit5paH5rWL\r\n"
    "6K+VMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB06h4SzOryi3d7PW9yN2wACC\r\n"
    "VxlduBQjVLWZlDKhFKkdZjve8mUyytSSbBj/rrzR2XmzUzofuNkUbAtje3DDJqN2\r\n"
    "MHQwHQYDVR0OBBYEFNtUldgBESf31bwTnYtApIctaSdtMB8GA1UdIwQYMBaAFNtU\r\n"
    "ldgBESf31bwTnYtApIctaSdtMAsGA1UdDwQEAwIBBjAJBgNVHREEAjAAMAkGA1Ud\r\n"
    "EgQCMAAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAzxzaG2vR\r\n"
    "zUnFFL3X3lRQ0IOJrb6cvkSZuaFd4bW2lgUCIHW6QGGnECDFMbDNz7Og9kjkt+3k\r\n"
    "FmEJWqEMYudBH3Ul\r\n"
    "-----END CERTIFICATE-----\r\n";

static char g_signedCertCms[] =
    "-----BEGIN CMS-----\r\n"
    "MIIDnAYJKoZIhvcNAQcCoIIDjTCCA4kCAQExDTALBglghkgBZQMEAgEwEwYJKoZI\r\n"
    "hvcNAQcBoAYEBAECAwSgggJiMIICXjCCAcegAwIBAgIGAXKnJjrAMA0GCSqGSIb3\r\n"
    "DQEBCwUAMEgxCzAJBgNVBAYTAkNOMQwwCgYDVQQIDANzaGExDTALBgNVBAcMBHhp\r\n"
    "YW4xDTALBgNVBAoMBHRlc3QxDTALBgNVBAMMBHRlc3QwHhcNMjQxMTIyMDkwNTIy\r\n"
    "WhcNMzQxMTIwMDkwNTIyWjBIMQswCQYDVQQGEwJDTjEMMAoGA1UECAwDc2hhMQ0w\r\n"
    "CwYDVQQHDAR4aWFuMQ0wCwYDVQQKDAR0ZXN0MQ0wCwYDVQQDDAR0ZXN0MIGfMA0G\r\n"
    "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6nCZTM16Rk2c4P/hwfVm++jqe6GCA/PXX\r\n"
    "Ge4YL218q1dTKMHBGEw8kXi0XLDcyyC2yUn8ywN2QSyly6ke9EE6PGfZywStLp4g\r\n"
    "2PTTWB04sS3aXT2y+fToiTXQ3AxfFYRpB+EgSdSCkJs6jKXVwbzu54kEtQTfs8Ud\r\n"
    "BQ9nVKaJLwIDAQABo1MwUTAdBgNVHQ4EFgQU6QXnt1smb2HRSO/2zuRQnz/SDxow\r\n"
    "HwYDVR0jBBgwFoAU6QXnt1smb2HRSO/2zuRQnz/SDxowDwYDVR0TAQH/BAUwAwEB\r\n"
    "/zANBgkqhkiG9w0BAQsFAAOBgQBPR/+5xzFG1XlTdgwWVvqVxvhGUkbMTGW0IviJ\r\n"
    "+jbKsi57vnVsOtFzEA6y+bYxxG/kEOcwLtzeVHOQA+ZU5SVcc+qc0dfFiWjL2PSA\r\n"
    "G4bpqSTjujpuUk+g8ugixbG1a26pkDJhNeB/E3eBIbeydSY0A/dIGb6vbGo6BSq2\r\n"
    "KvnWADGB+TCB9gIBATBSMEgxCzAJBgNVBAYTAkNOMQwwCgYDVQQIDANzaGExDTAL\r\n"
    "BgNVBAcMBHhpYW4xDTALBgNVBAoMBHRlc3QxDTALBgNVBAMMBHRlc3QCBgFypyY6\r\n"
    "wDALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEgYAgpDdvhRNSeKDoBxYyMjJU\r\n"
    "YAkTkx41LRJD5+NXCCUXu8tU/Inr6yg/9C3ZPMEpDItnTBD7dLPM/voMtZadmY4W\r\n"
    "KYcK1GDRnjBiTSgVP95b+bpYCu/ohFkZlZOavw+yi77ONGJa6sr34id/x6JNnO0Y\r\n"
    "+gk2IADNcyAy/rkdMwP/KQ==\r\n"
    "-----END CMS-----\r\n";

const CfEncodingBlob g_decryptEnvelopedDataPemStream = {
    .data = reinterpret_cast<uint8_t *>(g_privateKey),
    .len = strlen(g_privateKey) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

static const char g_testPwd[] = "123456";
static const char g_testPwdError[] = "1234";
static const uint8_t g_inContent[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
static const char g_helloWorldContent[] = "helloworld";


static const char g_digestSHA1[] = "SHA1";
static const char g_digestSHA256[] = "SHA256";
static const char g_digestSHA384[] = "SHA384";
static const char g_digestSHA512[] = "SHA512";
static const char g_digestSHA[] = "SHA";
static const char g_digestMD5[] = "MD5";

static CfResult CreateTrustCertsArray(HcfX509CertificateArray **trustCertsArray,
    const char *rootCertPem, const char *interCertPem)
{
    if (trustCertsArray == nullptr || rootCertPem == nullptr || interCertPem == nullptr) {
        return CF_INVALID_PARAMS;
    }

    uint32_t certNum = 2;
    *trustCertsArray = static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    if (*trustCertsArray == nullptr) {
        return CF_ERR_MALLOC;
    }

    (*trustCertsArray)->data = static_cast<HcfX509Certificate **>(CfMalloc(certNum * sizeof(HcfX509Certificate *), 0));
    if ((*trustCertsArray)->data == nullptr) {
        CfFree(*trustCertsArray);
        *trustCertsArray = nullptr;
        return CF_ERR_MALLOC;
    }
    (*trustCertsArray)->count = certNum;

    CfEncodingBlob rootCertBlob = {0};
    rootCertBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(rootCertPem));
    rootCertBlob.encodingFormat = CF_FORMAT_PEM;
    rootCertBlob.len = strlen(rootCertPem) + 1;

    CfResult ret = HcfX509CertificateCreate(&rootCertBlob, &(*trustCertsArray)->data[0]);
    if (ret != CF_SUCCESS) {
        CfFree((*trustCertsArray)->data);
        CfFree(*trustCertsArray);
        *trustCertsArray = nullptr;
        return ret;
    }

    CfEncodingBlob interCertBlob = {0};
    interCertBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(interCertPem));
    interCertBlob.encodingFormat = CF_FORMAT_PEM;
    interCertBlob.len = strlen(interCertPem) + 1;

    ret = HcfX509CertificateCreate(&interCertBlob, &(*trustCertsArray)->data[1]);
    if (ret != CF_SUCCESS) {
        CfObjDestroy((*trustCertsArray)->data[0]);
        CfFree((*trustCertsArray)->data);
        CfFree(*trustCertsArray);
        *trustCertsArray = nullptr;
        return ret;
    }

    return CF_SUCCESS;
}

static CfResult CreateSignerCertsArray(HcfX509CertificateArray **signerCertsArray, const char *leafCertPem)
{
    if (signerCertsArray == nullptr || leafCertPem == nullptr) {
        return CF_INVALID_PARAMS;
    }

    uint32_t certNum = 1;
    *signerCertsArray = static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    if (*signerCertsArray == nullptr) {
        return CF_ERR_MALLOC;
    }

    (*signerCertsArray)->data = static_cast<HcfX509Certificate **>(CfMalloc(certNum * sizeof(HcfX509Certificate *), 0));
    if ((*signerCertsArray)->data == nullptr) {
        CfFree(*signerCertsArray);
        *signerCertsArray = nullptr;
        return CF_ERR_MALLOC;
    }
    (*signerCertsArray)->count = certNum;
    
    CfEncodingBlob leafCertBlob = {0};
    leafCertBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(leafCertPem));
    leafCertBlob.encodingFormat = CF_FORMAT_PEM;
    leafCertBlob.len = strlen(leafCertPem) + 1;
    
    CfResult ret = HcfX509CertificateCreate(&leafCertBlob, &(*signerCertsArray)->data[0]);
    if (ret != CF_SUCCESS) {
        CfFree((*signerCertsArray)->data);
        CfFree(*signerCertsArray);
        *signerCertsArray = nullptr;
        return ret;
    }

    return CF_SUCCESS;
}

static void DestroyCertsArray(HcfX509CertificateArray **certsArray)
{
    if (certsArray == nullptr || *certsArray == nullptr) {
        return;
    }
    
    if ((*certsArray)->data != nullptr) {
        for (uint32_t i = 0; i < (*certsArray)->count; i++) {
            if ((*certsArray)->data[i] != nullptr) {
                CfObjDestroy((*certsArray)->data[i]);
            }
        }
        CfFree((*certsArray)->data);
    }
    CfFree(*certsArray);
    *certsArray = nullptr;
}

void CryptoX509CertCmsGeneratorTest::SetUpTestCase()
{
}

void CryptoX509CertCmsGeneratorTest::TearDownTestCase()
{
}

void CryptoX509CertCmsGeneratorTest::SetUp()
{
}

void CryptoX509CertCmsGeneratorTest::TearDown()
{
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, CreateCmsGenerator001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, CreateCmsGenerator002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfResult res = HcfCreateCmsGenerator(static_cast<HcfCmsContentType>(1), &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    CfObjDestroy(cmsGenerator);
    cmsGenerator = nullptr;
    res = HcfCreateCmsGenerator(static_cast<HcfCmsContentType>(-1), &cmsGenerator);
    EXPECT_EQ(res, CF_INVALID_PARAMS);
    EXPECT_EQ(cmsGenerator, nullptr);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, AddSigner001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyPasswordPemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA256);
    options->addCert = true;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA384);
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA512);
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    privateKey->privateKeyPassword = const_cast<char*>(g_testPwdError);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_CERT_INVALID_PRIVATE_KEY);

    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyPasswordPemStreamError);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, AddSigner002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertNoPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyNoPasswordPemStream);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    options->addCert = false;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA256);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA384);
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA512);
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, AddSigner003, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertPasswordPemStream2, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyPasswordDerStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA256);
    options->addCert = true;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA384);
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA512);
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    privateKey->privateKeyPassword = const_cast<char*>(g_testPwdError);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_CERT_INVALID_PRIVATE_KEY);

    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyPasswordDerStreamError);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, AddSigner004, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertNoPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyNoPasswordDerStream);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    options->addCert = false;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA256);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA384);
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = false;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    options->mdName = const_cast<char*>(g_digestSHA512);
    options->addCert = false;
    options->addAttr = false;
    options->addSmimeCapAttr = true;
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, AddSigner005, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertNoPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyNoPasswordPemStream);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    options->addCert = false;
    options->addAttr = true;
    options->addSmimeCapAttr = true;
    int count = 20;
    for (int i = 0; i < count; i++) {
        res = cmsGenerator->addSigner(cmsGenerator,  &(x509Cert->base), privateKey, options);
        EXPECT_EQ(res, CF_SUCCESS);
    }
    res = cmsGenerator->addSigner(cmsGenerator,  &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, AddSigner006, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertNoPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyNoPasswordPemStream);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA);
    options->addCert = true;
    options->addAttr = true;
    options->addSmimeCapAttr = true;

    res = cmsGenerator->addSigner(cmsGenerator,  &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    options->mdName = const_cast<char*>(g_digestMD5);
    res = cmsGenerator->addSigner(cmsGenerator,  &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->addSigner(cmsGenerator, nullptr, privateKey, options);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->addSigner(cmsGenerator,  &(x509Cert->base), nullptr, options);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->addSigner(cmsGenerator,  &(x509Cert->base), privateKey, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->addSigner(nullptr,  &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->addSigner(nullptr,  nullptr, nullptr, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, AddSigner007, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertEccPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyEccPemStream);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    options->addCert = true;
    options->addAttr = true;
    options->addSmimeCapAttr = true;

    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, AddCert001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertEccPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(x509Cert);

    ret = HcfX509CertificateCreate(&g_inCertPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(x509Cert);

    ret = HcfX509CertificateCreate(&g_inCertNoPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, AddCert002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertNoPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_SUCCESS);
    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    res = cmsGenerator->addCert(nullptr, &(x509Cert->base));
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->addCert(cmsGenerator, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->addCert(nullptr, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, DoFinal001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyPasswordPemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA1);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, DoFinal002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyPasswordPemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA256);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = CMS_PEM;
    cmsOptions->isDetachedContent = true;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, DoFinal003, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyPasswordPemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA384);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = TEXT;
    cmsOptions->outFormat = CMS_PEM;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, DoFinal004, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyPasswordPemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA512);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = TEXT;
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = true;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(privateKey);
    CfFree(options);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfBlobDataClearAndFree(&out);
    CfObjDestroy(cmsGenerator);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, DoFinal005, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    PrivateKeyInfo *privateKey = nullptr;
    HcfCmsSignerOptions *options = nullptr;
    HcfX509Certificate *x509Cert = nullptr;
    CfBlob out = {0, nullptr};
    CfBlob content;
    content.data = const_cast<uint8_t*>(g_inContent);
    content.size = sizeof(g_inContent);
    HcfCmsGeneratorOptions *cmsOptions = nullptr;

    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);

    CfResult ret = HcfX509CertificateCreate(&g_inCertPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    privateKey = (PrivateKeyInfo *)CfMalloc(sizeof(PrivateKeyInfo), 0);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_inKeyPasswordPemStream);
    privateKey->privateKeyPassword = const_cast<char*>(g_testPwd);

    options = (HcfCmsSignerOptions *)CfMalloc(sizeof(HcfCmsSignerOptions), 0);
    options->mdName = const_cast<char*>(g_digestSHA256);
    res = cmsGenerator->addSigner(cmsGenerator, &(x509Cert->base), privateKey, options);
    EXPECT_EQ(res, CF_SUCCESS);

    cmsOptions = (HcfCmsGeneratorOptions *)CfMalloc(sizeof(HcfCmsGeneratorOptions), 0);
    cmsOptions->dataFormat = static_cast<HcfCmsContentDataFormat>(2);
    cmsOptions->outFormat = CMS_DER;
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    cmsOptions->dataFormat = BINARY;
    cmsOptions->outFormat = static_cast<HcfCmsFormat>(2);
    cmsOptions->isDetachedContent = false;
    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->doFinal(nullptr, &content, cmsOptions, &out);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->doFinal(cmsGenerator, nullptr, cmsOptions, &out);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->doFinal(cmsGenerator, &content, nullptr, &out);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsGenerator->doFinal(cmsGenerator, &content, cmsOptions, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    CfFree(privateKey);
    CfFree(options);
    CfFree(cmsOptions);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}

static void FreeCmsOptions(HcfCmsParserSignedDataOptions *cmsOptions)
{
    if (cmsOptions != nullptr) {
        DestroyCertsArray(&cmsOptions->trustCerts);
        DestroyCertsArray(&cmsOptions->signerCerts);
        CfFree(cmsOptions);
    }
}

static CfResult BuildCmsData(HcfCmsParserSignedDataOptions **cmsOptions)
{
    HcfX509CertificateArray *trustCertsArray = nullptr;
    HcfX509CertificateArray *signerCertsArray = nullptr;
    CfResult res = CreateTrustCertsArray(&trustCertsArray, g_verifyRootPem, g_interPem);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(trustCertsArray, nullptr);

    res = CreateSignerCertsArray(&signerCertsArray, g_testleftPem);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(signerCertsArray, nullptr);

    HcfCmsParserSignedDataOptions *tmpCmsOptions = static_cast<HcfCmsParserSignedDataOptions *>(
        CfMalloc(sizeof(HcfCmsParserSignedDataOptions), 0));
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(tmpCmsOptions, nullptr);

    CfBlob externalContent;
    externalContent.data = const_cast<uint8_t*>(g_inContent);
    externalContent.size = sizeof(g_inContent);

    tmpCmsOptions->trustCerts = trustCertsArray;
    tmpCmsOptions->signerCerts = signerCertsArray;
    tmpCmsOptions->contentData = &externalContent;
    tmpCmsOptions->contentDataFormat = BINARY;
    *cmsOptions = tmpCmsOptions;
    return CF_SUCCESS;
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Verify001, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;
    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    HcfCmsParserSignedDataOptions *cmsOptions = nullptr;
    res = BuildCmsData(&cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsOptions, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    res = cmsParser->verifySignedData(cmsParser, cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(cmsParser);
    FreeCmsOptions(cmsOptions);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Verify002, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    res = cmsParser->verifySignedData(cmsParser, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->verifySignedData(nullptr, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Verify003, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    HcfX509CertificateArray *signerCertsArray = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = CreateSignerCertsArray(&signerCertsArray, g_testleftPem);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(signerCertsArray, nullptr);

    res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsParserSignedDataOptions *cmsOptions = static_cast<HcfCmsParserSignedDataOptions *>(
        CfMalloc(sizeof(HcfCmsParserSignedDataOptions), 0));
    EXPECT_NE(cmsOptions, nullptr);

    cmsOptions->trustCerts = nullptr;
    cmsOptions->signerCerts = signerCertsArray;
    cmsOptions->contentData = nullptr;
    cmsOptions->contentDataFormat = BINARY;

    res = cmsParser->verifySignedData(cmsParser, cmsOptions);
    EXPECT_NE(res, CF_SUCCESS);

    CfFree(cmsOptions);
    CfObjDestroy(cmsParser);
    DestroyCertsArray(&signerCertsArray);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Verify004, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;
    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    HcfCmsParserSignedDataOptions *cmsOptions = nullptr;
    res = BuildCmsData(&cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsOptions, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    res = cmsParser->verifySignedData(cmsParser, cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(cmsParser);
    FreeCmsOptions(cmsOptions);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Verify005, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    
    CfResult res = HcfCreateCmsParser(nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, nullptr, CMS_PEM);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->setRawData(nullptr, nullptr, CMS_PEM);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Verify006, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsContentType contentType;
    res = cmsParser->getContentType(cmsParser, &contentType);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(contentType, SIGNED_DATA);

    CfBlob contentData = {0, nullptr};
    res = cmsParser->getContentData(cmsParser, &contentData);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(contentData.data, nullptr);
    EXPECT_GT(contentData.size, 0);

    uint8_t inContent[] = {0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(contentData.size, sizeof(inContent));
    EXPECT_EQ(memcmp(contentData.data, inContent, sizeof(inContent)), 0);

    CfBlobDataClearAndFree(&contentData);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Verify007, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfX509CertificateArray certs = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_ALL_CERTS, &certs);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(certs.data, nullptr);
    EXPECT_GT(certs.count, 0);

    EXPECT_GE(certs.count, 1);

    if (certs.data != nullptr) {
        for (uint32_t i = 0; i < certs.count; i++) {
            if (certs.data[i] != nullptr) {
                CfObjDestroy(certs.data[i]);
            }
        }
        CfFree(certs.data);
    }

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Decrypt001, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_encryptedCmsPem));
    cmsData.size = strlen(g_encryptedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsContentType contentType;
    res = cmsParser->getContentType(cmsParser, &contentType);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(contentType, ENVELOPED_DATA);

    HcfCmsParserDecryptEnvelopedDataOptions *decryptOptions = static_cast<HcfCmsParserDecryptEnvelopedDataOptions *>(
            CfMalloc(sizeof(HcfCmsParserDecryptEnvelopedDataOptions), 0));
    EXPECT_NE(decryptOptions, nullptr);

    PrivateKeyInfo *privateKey = static_cast<PrivateKeyInfo *>(
        CfMalloc(sizeof(PrivateKeyInfo), 0));
    EXPECT_NE(privateKey, nullptr);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_decryptEnvelopedDataPemStream);
    privateKey->privateKeyPassword = nullptr;

    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob certBlob = {0};
    certBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pubKey));
    certBlob.encodingFormat = CF_FORMAT_PEM;
    certBlob.len = strlen(g_pubKey) + 1;

    res = HcfX509CertificateCreate(&certBlob, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    decryptOptions->privateKey = privateKey;
    decryptOptions->cert = x509Cert;
    decryptOptions->encryptedContentData = nullptr;
    decryptOptions->contentDataFormat = BINARY;

    CfBlob decryptedData = {0, nullptr};
    res = cmsParser->decryptEnvelopedData(cmsParser, decryptOptions, &decryptedData);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(decryptedData.data, nullptr);
    EXPECT_GT(decryptedData.size, 0);

    EXPECT_EQ(decryptedData.size, strlen(g_helloWorldContent));
    EXPECT_EQ(memcmp(decryptedData.data, g_helloWorldContent, strlen(g_helloWorldContent)), 0);
    
    CfBlobDataClearAndFree(&decryptedData);
    CfFree(decryptOptions);
    CfFree(privateKey);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Decrypt002, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;

    CfResult res = HcfCreateCmsParser(nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->decryptEnvelopedData(nullptr, nullptr, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    res = cmsParser->decryptEnvelopedData(cmsParser, nullptr, nullptr);
    EXPECT_EQ(res, CF_INVALID_PARAMS);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Decrypt003, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_encryptedCmsPem));
    cmsData.size = strlen(g_encryptedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsParserDecryptEnvelopedDataOptions *decryptOptions =
        static_cast<HcfCmsParserDecryptEnvelopedDataOptions *>(
            CfMalloc(sizeof(HcfCmsParserDecryptEnvelopedDataOptions), 0));
    EXPECT_NE(decryptOptions, nullptr);
    
    decryptOptions->privateKey = nullptr;
    decryptOptions->cert = nullptr;
    decryptOptions->encryptedContentData = nullptr;
    decryptOptions->contentDataFormat = BINARY;

    CfBlob decryptedData = {0, nullptr};
    res = cmsParser->decryptEnvelopedData(cmsParser, decryptOptions, &decryptedData);
    EXPECT_NE(res, CF_SUCCESS);

    CfFree(decryptOptions);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Decrypt004, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_encryptedCmsPem));
    cmsData.size = strlen(g_encryptedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsParserDecryptEnvelopedDataOptions *decryptOptions =
        static_cast<HcfCmsParserDecryptEnvelopedDataOptions *>(
            CfMalloc(sizeof(HcfCmsParserDecryptEnvelopedDataOptions), 0));
    EXPECT_NE(decryptOptions, nullptr);

    PrivateKeyInfo *privateKey = static_cast<PrivateKeyInfo *>(
        CfMalloc(sizeof(PrivateKeyInfo), 0));
    EXPECT_NE(privateKey, nullptr);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_decryptEnvelopedDataPemStream);
    privateKey->privateKeyPassword = nullptr;

    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob certBlob = {0};
    certBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pubKey));
    certBlob.encodingFormat = CF_FORMAT_PEM;
    certBlob.len = strlen(g_pubKey) + 1;

    res = HcfX509CertificateCreate(&certBlob, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    CfBlob encryptedContentData = {0, nullptr};
    res = cmsParser->getContentData(cmsParser, &encryptedContentData);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    EXPECT_EQ(encryptedContentData.data, nullptr);
    EXPECT_EQ(encryptedContentData.size, 0);

    decryptOptions->privateKey = privateKey;
    decryptOptions->cert = x509Cert;
    decryptOptions->encryptedContentData = &encryptedContentData;
    decryptOptions->contentDataFormat = BINARY;

    CfBlob decryptedData = {0, nullptr};
    res = cmsParser->decryptEnvelopedData(cmsParser, decryptOptions, &decryptedData);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(decryptedData.data, nullptr);
    EXPECT_GT(decryptedData.size, 0);

    EXPECT_EQ(decryptedData.size, strlen(g_helloWorldContent));
    EXPECT_EQ(memcmp(decryptedData.data, g_helloWorldContent, strlen(g_helloWorldContent)), 0);

    CfBlobDataClearAndFree(&decryptedData);
    CfBlobDataClearAndFree(&encryptedContentData);
    CfFree(decryptOptions);
    CfFree(privateKey);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, Decrypt005, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsContentType contentType;
    res = cmsParser->getContentType(cmsParser, &contentType);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(contentType, SIGNED_DATA);

    HcfCmsParserDecryptEnvelopedDataOptions *decryptOptions =
        static_cast<HcfCmsParserDecryptEnvelopedDataOptions *>(
            CfMalloc(sizeof(HcfCmsParserDecryptEnvelopedDataOptions), 0));
    EXPECT_NE(decryptOptions, nullptr);

    PrivateKeyInfo *privateKey = static_cast<PrivateKeyInfo *>(
        CfMalloc(sizeof(PrivateKeyInfo), 0));
    EXPECT_NE(privateKey, nullptr);
    privateKey->privateKey = const_cast<CfEncodingBlob*>(&g_decryptEnvelopedDataPemStream);
    privateKey->privateKeyPassword = nullptr;

    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob certBlob = {0};
    certBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_pubKey));
    certBlob.encodingFormat = CF_FORMAT_PEM;
    certBlob.len = strlen(g_pubKey) + 1;

    res = HcfX509CertificateCreate(&certBlob, &x509Cert);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    decryptOptions->privateKey = privateKey;
    decryptOptions->cert = x509Cert;
    decryptOptions->encryptedContentData = nullptr;
    decryptOptions->contentDataFormat = BINARY;

    CfBlob decryptedData = {0, nullptr};
    res = cmsParser->decryptEnvelopedData(cmsParser, decryptOptions, &decryptedData);
    EXPECT_NE(res, CF_SUCCESS);
    
    CfFree(decryptOptions);
    CfFree(privateKey);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, VerifyWithCustomCerts, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    HcfX509CertificateArray *trustCertsArray = nullptr;
    HcfX509CertificateArray *signerCertsArray = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_emmptyDataCms));
    cmsData.size = strlen(g_emmptyDataCms) + 1;

    CfResult res = CreateTrustCertsArray(&trustCertsArray, g_emptyRootCert, g_emptyMiddleCert);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(trustCertsArray, nullptr);

    res = CreateSignerCertsArray(&signerCertsArray, g_testleftPem);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(signerCertsArray, nullptr);

    res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfCmsParserSignedDataOptions *cmsOptions = static_cast<HcfCmsParserSignedDataOptions *>(
        CfMalloc(sizeof(HcfCmsParserSignedDataOptions), 0));
    EXPECT_NE(cmsOptions, nullptr);

    cmsOptions->trustCerts = trustCertsArray;
    cmsOptions->signerCerts = signerCertsArray;
    cmsOptions->contentData = nullptr;
    cmsOptions->contentDataFormat = BINARY;

    res = cmsParser->verifySignedData(cmsParser, cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);

    CfFree(cmsOptions);
    CfObjDestroy(cmsParser);
    DestroyCertsArray(&trustCertsArray);
    DestroyCertsArray(&signerCertsArray);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, VerifyDerFormat, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = g_testRsaKeyNoPasswordDer;
    cmsData.size = sizeof(g_testRsaKeyNoPasswordDer);

    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_DER);
    EXPECT_NE(res, CF_SUCCESS);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, VerifyGetCerts001, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCmsPem));
    cmsData.size = strlen(g_signedCmsPem) + 1;
    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);

    HcfCmsParserSignedDataOptions *cmsOptions = nullptr;
    res = BuildCmsData(&cmsOptions);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsOptions, nullptr);

    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfX509CertificateArray allCerts = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_ALL_CERTS, &allCerts);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(allCerts.data, nullptr);
    EXPECT_GT(allCerts.count, 0);

    if (allCerts.data != nullptr) {
        for (uint32_t i = 0; i < allCerts.count; i++) {
            if (allCerts.data[i] != nullptr) {
                CfObjDestroy(allCerts.data[i]);
            }
        }
        CfFree(allCerts.data);
    }

    FreeCmsOptions(cmsOptions);
    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, VerifyGetCerts002, TestSize.Level0)
{
    HcfCmsParser *cmsParser = nullptr;
    CfBlob cmsData;
    cmsData.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_signedCertCms));
    cmsData.size = strlen(g_signedCertCms) + 1;
    CfResult res = HcfCreateCmsParser(&cmsParser);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsParser, nullptr);


    res = cmsParser->setRawData(cmsParser, &cmsData, CMS_PEM);
    EXPECT_EQ(res, CF_SUCCESS);

    HcfX509CertificateArray signerCerts = {nullptr, 0};
    res = cmsParser->getCerts(cmsParser, CMS_CERT_SIGNER_CERTS, &signerCerts);
    EXPECT_NE(res, CF_SUCCESS);

    CfObjDestroy(cmsParser);
}

HWTEST_F(CryptoX509CertCmsGeneratorTest, VerifyErr001, TestSize.Level0)
{
    CfResult ret = HcfCmsParserSpiCreate(nullptr);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);
}
}