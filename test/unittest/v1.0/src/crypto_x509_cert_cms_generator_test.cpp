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

static const char g_testPwd[] = "123456";
static const char g_testPwdError[] = "1234";
static const uint8_t g_inContent[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

static const char g_digestSHA1[] = "SHA1";
static const char g_digestSHA256[] = "SHA256";
static const char g_digestSHA384[] = "SHA384";
static const char g_digestSHA512[] = "SHA512";
static const char g_digestSHA[] = "SHA";
static const char g_digestMD5[] = "MD5";

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
    EXPECT_EQ(res, CF_INVALID_PARAMS);
    EXPECT_EQ(cmsGenerator, nullptr);
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
    EXPECT_EQ(res, CF_NOT_SUPPORT);

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
}