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

static uint8_t g_testRsaKeyPasswordDer[] = {
0x30, 0x82, 0x02, 0x5D, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xBA, 0x9C, 0x26, 0x53, 0x33,
0x5E, 0x91, 0x93, 0x67, 0x38, 0x3F, 0xF8, 0x70, 0x7D, 0x59, 0xBE, 0xFA, 0x3A, 0x9E, 0xE8, 0x60,
0x80, 0xFC, 0xF5, 0xD7, 0x19, 0xEE, 0x18, 0x2F, 0x6D, 0x7C, 0xAB, 0x57, 0x53, 0x28, 0xC1, 0xC1,
0x18, 0x4C, 0x3C, 0x91, 0x78, 0xB4, 0x5C, 0xB0, 0xDC, 0xCB, 0x20, 0xB6, 0xC9, 0x49, 0xFC, 0xCB,
0x03, 0x76, 0x41, 0x2C, 0xA5, 0xCB, 0xA9, 0x1E, 0xF4, 0x41, 0x3A, 0x3C, 0x67, 0xD9, 0xCB, 0x04,
0xAD, 0x2E, 0x9E, 0x20, 0xD8, 0xF4, 0xD3, 0x58, 0x1D, 0x38, 0xB1, 0x2D, 0xDA, 0x5D, 0x3D, 0xB2,
0xF9, 0xF4, 0xE8, 0x89, 0x35, 0xD0, 0xDC, 0x0C, 0x5F, 0x15, 0x84, 0x69, 0x07, 0xE1, 0x20, 0x49,
0xD4, 0x82, 0x90, 0x9B, 0x3A, 0x8C, 0xA5, 0xD5, 0xC1, 0xBC, 0xEE, 0xE7, 0x89, 0x04, 0xB5, 0x04,
0xDF, 0xB3, 0xC5, 0x1D, 0x05, 0x0F, 0x67, 0x54, 0xA6, 0x89, 0x2F, 0x02, 0x03, 0x01, 0x00, 0x01,
0x02, 0x81, 0x80, 0x6C, 0x0F, 0xC6, 0x85, 0xC1, 0xA6, 0x8E, 0xC8, 0x7C, 0x2A, 0x6F, 0xA8, 0xEF,
0x83, 0x37, 0x38, 0x47, 0x71, 0x30, 0xDA, 0x42, 0x20, 0x0F, 0xDC, 0x50, 0xFE, 0x9C, 0x08, 0xF7,
0x56, 0x00, 0xAE, 0xBB, 0xF7, 0xD5, 0x0F, 0x36, 0x41, 0x5A, 0xCC, 0x6C, 0x35, 0x28, 0xC4, 0xD0,
0x4A, 0x5B, 0x7A, 0x8B, 0x3E, 0xCF, 0x10, 0x8B, 0x83, 0x6A, 0xB4, 0x5D, 0x25, 0x79, 0x65, 0x6B,
0x1E, 0x68, 0xB2, 0x51, 0x3F, 0xA0, 0x03, 0x07, 0xB1, 0xAA, 0xA0, 0x19, 0x51, 0x06, 0x65, 0x1B,
0x29, 0xD6, 0xC6, 0xDF, 0x69, 0xF2, 0xD1, 0xD7, 0xCA, 0xAF, 0xA6, 0x42, 0xC6, 0x1A, 0xD4, 0xF9,
0x60, 0xFD, 0x90, 0xB4, 0x1A, 0xC9, 0x27, 0x0E, 0xD5, 0xFA, 0x4C, 0xFF, 0x12, 0x8A, 0x81, 0x92,
0xD0, 0xA6, 0x11, 0x9C, 0x2E, 0x4B, 0x59, 0xDB, 0xCC, 0x1E, 0x55, 0x70, 0x50, 0x3B, 0xCC, 0xC0,
0xB3, 0x23, 0xC1, 0x02, 0x41, 0x00, 0xF0, 0x9A, 0x34, 0xE1, 0xEB, 0x0E, 0x5C, 0x9F, 0x73, 0x0F,
0x05, 0xE7, 0x67, 0xE9, 0x36, 0x31, 0xC1, 0x38, 0xFB, 0x7A, 0x5D, 0xE2, 0xDE, 0xCE, 0xC5, 0x7A,
0x92, 0x41, 0x8D, 0xC7, 0xAA, 0xA9, 0x7E, 0x0E, 0x5A, 0x08, 0x9C, 0xDB, 0x97, 0x54, 0x6A, 0x16,
0x55, 0xDA, 0x42, 0xF5, 0x0E, 0xD1, 0x59, 0xC3, 0xB7, 0xB5, 0x72, 0x5C, 0xBA, 0x9E, 0x1E, 0x1A,
0x79, 0x05, 0x8D, 0x10, 0xCC, 0x0F, 0x02, 0x41, 0x00, 0xC6, 0x8D, 0x62, 0x68, 0x99, 0x7A, 0x37,
0x82, 0x93, 0x26, 0x5B, 0x1B, 0x10, 0xCC, 0x48, 0xB3, 0x56, 0x33, 0xE2, 0xFE, 0xD8, 0x1A, 0xF1,
0x1A, 0x09, 0xCD, 0x37, 0xA2, 0x83, 0x76, 0x45, 0x2B, 0x7D, 0x23, 0xF9, 0xC4, 0x89, 0x76, 0xAC,
0xD1, 0x9D, 0xDC, 0xC9, 0xD1, 0xFA, 0xC2, 0xA3, 0x06, 0x26, 0xDE, 0x3E, 0x00, 0x80, 0x8F, 0xD7,
0xC5, 0x89, 0xE0, 0x6F, 0x43, 0xC0, 0x79, 0xD0, 0xE1, 0x02, 0x41, 0x00, 0xA3, 0xE5, 0x37, 0xAE,
0xC9, 0x72, 0xE0, 0x0F, 0x51, 0xCE, 0x63, 0x04, 0x2E, 0x19, 0x83, 0xEC, 0x42, 0xA6, 0x31, 0x50,
0x3A, 0xD2, 0x47, 0x5A, 0x6C, 0xD5, 0x40, 0xF9, 0xDC, 0xBD, 0xAD, 0x78, 0x85, 0xC0, 0xFA, 0xFD,
0xB0, 0xF4, 0x38, 0xD2, 0xAC, 0xED, 0x88, 0x10, 0x04, 0xDA, 0x6F, 0xFC, 0x95, 0xFC, 0x27, 0x91,
0x37, 0x55, 0x09, 0x5E, 0x9A, 0x3D, 0x08, 0x41, 0x8A, 0xC5, 0x6D, 0x6B, 0x02, 0x41, 0x00, 0x80,
0xD1, 0x03, 0xB2, 0xA7, 0x38, 0x62, 0xC1, 0x45, 0x64, 0xD2, 0x20, 0xEA, 0x32, 0x0F, 0x4C, 0xC2,
0xB5, 0xA1, 0x25, 0x03, 0xE1, 0xDE, 0xE0, 0xAC, 0xD1, 0x46, 0xB2, 0x1A, 0x26, 0x66, 0x54, 0x03,
0xB9, 0x8E, 0x77, 0x53, 0x53, 0xFA, 0x65, 0x78, 0xCC, 0xE0, 0xE7, 0x69, 0x90, 0x53, 0xA2, 0x4F,
0x1F, 0x4B, 0x0C, 0x9A, 0x5C, 0x38, 0x7A, 0x41, 0xAC, 0xA9, 0xA3, 0x44, 0x42, 0x04, 0x21, 0x02,
0x40, 0x26, 0x3C, 0x4E, 0xCA, 0xD7, 0x42, 0x3E, 0xC0, 0xF5, 0xC6, 0x54, 0xA0, 0xAF, 0x3B, 0x7F,
0xF6, 0x83, 0x22, 0x89, 0x58, 0xD4, 0xEF, 0x36, 0x42, 0x17, 0x2C, 0x93, 0x65, 0x48, 0xE6, 0x06,
0x32, 0x62, 0xA6, 0xFC, 0x8A, 0x3B, 0x70, 0x69, 0x96, 0xE3, 0xBC, 0xD7, 0x3A, 0xB2, 0x76, 0x39,
0xBF, 0xF8, 0x9B, 0x1B, 0xC3, 0x4C, 0x2F, 0x09, 0x46, 0x23, 0xD7, 0xD0, 0x53, 0x83, 0xC2, 0x69,
0x8B
};

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

const CfEncodingBlob g_inCertPasswordPemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaCertPasswordPem),
    .len = strlen(g_testRsaCertPasswordPem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyPasswordPemStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaKeyPasswordPem),
    .len = strlen(g_testRsaKeyPasswordPem) + 1,
    .encodingFormat = CF_FORMAT_PEM
};

const CfEncodingBlob g_inKeyPasswordDerStream = {
    .data = reinterpret_cast<uint8_t *>(g_testRsaKeyPasswordDer),
    .len = sizeof(g_testRsaKeyPasswordDer),
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
// HcfCreateCmsGenerator正常场景
HWTEST_F(CryptoX509CertCmsGeneratorTest, CreateCmsGenerator001, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfResult res = HcfCreateCmsGenerator(SIGNED_DATA, &cmsGenerator);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(cmsGenerator, nullptr);
    CfObjDestroy(cmsGenerator);
}
// HcfCreateCmsGenerator异常场景
HWTEST_F(CryptoX509CertCmsGeneratorTest, CreateCmsGenerator002, TestSize.Level0)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfResult res = HcfCreateCmsGenerator(static_cast<HcfCmsContentType>(1), &cmsGenerator);
    EXPECT_EQ(res, CF_NOT_SUPPORT);
    EXPECT_EQ(cmsGenerator, nullptr);
    res = HcfCreateCmsGenerator(static_cast<HcfCmsContentType>(-1), &cmsGenerator);
    EXPECT_EQ(res, CF_NOT_SUPPORT);
    EXPECT_EQ(cmsGenerator, nullptr);
}
// 证书私钥带密码pem格式addSigner正常场景
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

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}
// 证书私钥不带密码pem格式addSigner正常场景
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
// 证书私钥带密码der格式addSigner正常场景
HWTEST_F(CryptoX509CertCmsGeneratorTest, AddSigner003, TestSize.Level0)
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

    CfFree(privateKey);
    CfFree(options);
    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}
// 证书私钥不带密码Der格式addSigner正常场景
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
// 证书私钥不带密码pem格式addSigner大于20个异常场景
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
// 证书私钥不带密码pem格式addSigner参数为空异常场景
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
// 证书私钥为ECCpem格式addSigner异常场景
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
// AddCert正常场景
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

    ret = HcfX509CertificateCreate(&g_inCertPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_SUCCESS);

    ret = HcfX509CertificateCreate(&g_inCertNoPasswordPemStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    res = cmsGenerator->addCert(cmsGenerator, &(x509Cert->base));
    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(x509Cert);
    CfObjDestroy(cmsGenerator);
}
// AddCert参数为空异常场景
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
// doFinal正常场景
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
    CfObjDestroy(cmsGenerator);
}

// doFinal异常场景
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