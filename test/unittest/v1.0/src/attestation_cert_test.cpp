
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <string>
#include <gtest/gtest.h>
#include <openssl/pem.h>
#include "securec.h"
#include "cf_memory.h"
#include "hm_attestation_cert_verify.h"
#include "attestation_cert_ext_legacy.h"
#include "attestation_cert_ext.h"
#include "attestation_cert_verify.h"
#include "attestation_common.h"

using namespace std;
using namespace testing::ext;

namespace {
class CfAttestationTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CfAttestationTest::SetUpTestCase(void)
{
}

void CfAttestationTest::TearDownTestCase(void)
{
}

void CfAttestationTest::SetUp()
{
}

void CfAttestationTest::TearDown()
{
}
 
const char *EC_ROOT_CA = "-----BEGIN CERTIFICATE-----\n"
"MIIB2TCCAX+gAwIBAgIFAt/cGLEwCgYIKoZIzj0EAwIwQzEPMA0GA1UECgwGVEVT\n"
"VCBYMTAwLgYDVQQDDCdURVNUIFggRUNDIERldmljZSBBdHRlc3RhdGlvbiBSb290\n"
"IENBIDEwHhcNMjUwNjA3MDkzMTE5WhcNNDUwNDAzMDkzMTE5WjBDMQ8wDQYDVQQK\n"
"DAZURVNUIFgxMDAuBgNVBAMMJ1RFU1QgWCBFQ0MgRGV2aWNlIEF0dGVzdGF0aW9u\n"
"IFJvb3QgQ0EgMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNIRo0npO5bdiWHm\n"
"5+Gfe90YWh+8RmGlPI4VnP2gDJamPlZfKSokvcPX72IIZZen0KYoU92jlPoLy4mo\n"
"vCoFFYCjYDBeMB0GA1UdDgQWBBT8QJ0aBENv/QK9b9yA+whHSj9AJDAfBgNVHSME\n"
"GDAWgBT8QJ0aBENv/QK9b9yA+whHSj9AJDAPBgNVHRMBAf8EBTADAQH/MAsGA1Ud\n"
"DwQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiEA/AuETYSOLM4MXvZYv14QimHv8slQ\n"
"RRCItMDzYbUO6hQCIH8k97AK+7bFipGLJIjd8hY4oG7iWlGgUtwU9Kx6ne7q\n"
"-----END CERTIFICATE-----";

const char *EC_APP_CERT = "-----BEGIN CERTIFICATE-----\n"
"MIIBrDCCAVGgAwIBAgIFBTPn/LEwCgYIKoZIzj0EAwIwTTEPMA0GA1UECgwGVEVT\n"
"VCBYMS0wKwYDVQQDDCRURVNUIFggRUNDIERldmljZSBBdHRlc3RhdGlvbiBERVZJ\n"
"Q0UxCzAJBgNVBAYTAkNOMB4XDTI1MDYwNzA5MzExOVoXDTQ1MDQwMzA5MzExOVow\n"
"ETEPMA0GA1UECwwGZnV0dXJlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQTyG\n"
"YoRJ4XYWEIi0aQYn5dPTkXlA7pc5TBuK5/9BBlrjiuxz571TDXR9fazshKW9Z95O\n"
"d+zh1MvVoPDIMp2kjaNaMFgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwHQYDVR0O\n"
"BBYEFL/oq2cWVndUXzTFzScpHiX1qn/FMB8GA1UdIwQYMBaAFFaxkHCk+M2NY+6n\n"
"gTqmGhCWPFq5MAoGCCqGSM49BAMCA0kAMEYCIQC/+lDbY/ZjvZE9q4ZcaoTaY56D\n"
"md7dYhvERA8S3lVjbQIhAJkNkVQd/cQFNDSSDep1OpGAxHRFi0fBB5gRF4wo2fHx\n"
"-----END CERTIFICATE-----";

const char *EC_DEVICE_CERT = "-----BEGIN CERTIFICATE-----\n"
"MIIB7DCCAZGgAwIBAgIFAt/cGLIwCgYIKoZIzj0EAwIwSzEPMA0GA1UECgwGVEVT\n"
"VCBYMSswKQYDVQQDDCJURVNUIFggRUNDIERldmljZSBBdHRlc3RhdGlvbiBDQSAx\n"
"MQswCQYDVQQGEwJDTjAeFw0yNTA2MDcwOTMxMTlaFw00NTA0MDMwOTMxMTlaME0x\n"
"DzANBgNVBAoMBlRFU1QgWDEtMCsGA1UEAwwkVEVTVCBYIEVDQyBEZXZpY2UgQXR0\n"
"ZXN0YXRpb24gREVWSUNFMQswCQYDVQQGEwJDTjBZMBMGByqGSM49AgEGCCqGSM49\n"
"AwEHA0IABP5NtT48Y7hI8goGFfSmtZMuANRYgG1eB2qnalZOb5kGpABpnqdDaKvo\n"
"Fv+k6xkjOJ5a8REuN4rDnVtpkg9ObE2jYDBeMB0GA1UdDgQWBBRWsZBwpPjNjWPu\n"
"p4E6phoQljxauTAfBgNVHSMEGDAWgBQtzg7qzZ2yDH1ZUzGgPTSJoMUBLjAPBgNV\n"
"HRMBAf8EBTADAQH/MAsGA1UdDwQEAwIBBjAKBggqhkjOPQQDAgNJADBGAiEAmmX4\n"
"N55vDsPijPbE6Q2I7enHQWevRnJzfzJCoK5lzFQCIQD6dIN1XV9rMh0dTXtPQVmO\n"
"QD1SSlQCb2fuy+oQgyDD2Q==\n"
"-----END CERTIFICATE-----";

const char *EC_SUB_CA_CERT = "-----BEGIN CERTIFICATE-----\n"
"MIIB4jCCAYegAwIBAgIFAt/cGLIwCgYIKoZIzj0EAwIwQzEPMA0GA1UECgwGVEVT\n"
"VCBYMTAwLgYDVQQDDCdURVNUIFggRUNDIERldmljZSBBdHRlc3RhdGlvbiBSb290\n"
"IENBIDEwHhcNMjUwNjA3MDkzMTE5WhcNNDUwNDAzMDkzMTE5WjBLMQ8wDQYDVQQK\n"
"DAZURVNUIFgxKzApBgNVBAMMIlRFU1QgWCBFQ0MgRGV2aWNlIEF0dGVzdGF0aW9u\n"
"IENBIDExCzAJBgNVBAYTAkNOMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsqsm\n"
"SmDeZ12OsC+/6+b7z2w7ga9IOqdB4JohzWMtrIsrFSpPMwtI7XeMwr3+4I7l/KGM\n"
"bYxVaekO0D0su64EBaNgMF4wHQYDVR0OBBYEFC3ODurNnbIMfVlTMaA9NImgxQEu\n"
"MB8GA1UdIwQYMBaAFPxAnRoEQ2/9Ar1v3ID7CEdKP0AkMA8GA1UdEwEB/wQFMAMB\n"
"Af8wCwYDVR0PBAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQDybyPn3hcuCQ50CVHb\n"
"IpwSJlzGmwltoKkh0TyYDvA9LQIhAI4wq85zQ/M2Z1yrrx+yYttySw+9dxQ/wW3P\n"
"OHJr6vQk\n"
"-----END CERTIFICATE-----";

const char *RSA_ROOT_CA = "-----BEGIN CERTIFICATE-----\n"
"MIIDZTCCAk2gAwIBAgIFAt/cGLEwDQYJKoZIhvcNAQELBQAwQzEPMA0GA1UECgwG\n"
"VEVTVCBYMTAwLgYDVQQDDCdURVNUIFggUlNBIERldmljZSBBdHRlc3RhdGlvbiBS\n"
"b290IENBIDEwHhcNMjUwNjA3MDcwOTI5WhcNNDUwNDAzMDcwOTI5WjBDMQ8wDQYD\n"
"VQQKDAZURVNUIFgxMDAuBgNVBAMMJ1RFU1QgWCBSU0EgRGV2aWNlIEF0dGVzdGF0\n"
"aW9uIFJvb3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM4m\n"
"Io2yEXYN8ltRBdiEjxhYy8Z6xZIQZfBwC0hUmio2PQXAlPzwv4OCuBFgi1hcvZL9\n"
"PsbvIYG2APKVc31ktiMpPJmSWkxTu/SKA1cbc5APEFx+PTJhVZ5F3I3rwRwGQybt\n"
"NrxvE946Q7eauna9jkyURJtuN2bnxGtON0rcrdW10tLN2DBnLMxJYlTw5gMIzfWQ\n"
"02CYr5D3DPcovyaF8661N/JEGHgQih3H6attna7Gw663YQiWy2tpXiS2BFZU1PYl\n"
"C9iHbqACZ5cLIIHg4X9Y0Zhqun9O0lprJHJZua3DW8yRqlyhstWPpFtGBKtKLe6J\n"
"adsesMuTpP5M87EN7VcCAwEAAaNgMF4wHQYDVR0OBBYEFBbEAVsSD7EoOcDfCqMI\n"
"snoSmjc3MB8GA1UdIwQYMBaAFBbEAVsSD7EoOcDfCqMIsnoSmjc3MA8GA1UdEwEB\n"
"/wQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBPCOxCd7in\n"
"UCXOjX0/06t+baBCeU9RN3cz3ArI6R73LoJlBXMhEc7xzzXMKzVN3uZEBTRDInNU\n"
"XIE730Y07QrIL5Q5Jqc8bb2W2xWksvBbV+x6uh/zw0kRnOnJwCxgpaXCCQ8Pfukn\n"
"rb7rOu5+A4QBZwu2IvSN7swxYoIgRD81XOMpyIsNAbuI7w6lvpWuXeG/gyeVwQ9P\n"
"TPgxcZRMrTa/9bJr1aWYJPjOw4QkarHx5IVRhZR57k2mZ9cOVlFEV0KInQyF1LrU\n"
"9yIAFV0nHSp0zt8dBdtxmNiWEZTBh2f4BrZ5Lz41GSoD8OJi9u12ySxgaAH43LPN\n"
"UBoMYLvARABk\n"
"-----END CERTIFICATE-----";

const char *RSA_APP_CERT = "-----BEGIN CERTIFICATE-----\n"
"MIIDOzCCAiOgAwIBAgIFBTPn/LEwDQYJKoZIhvcNAQELBQAwTTEPMA0GA1UECgwG\n"
"VEVTVCBYMS0wKwYDVQQDDCRURVNUIFggUlNBIERldmljZSBBdHRlc3RhdGlvbiBE\n"
"RVZJQ0UxCzAJBgNVBAYTAkNOMB4XDTI1MDYwNzA3MDkzMFoXDTQ1MDQwMzA3MDkz\n"
"MFowFTETMBEGA1UECwwKcnNhIGZ1dHVyZTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n"
"ADCCAQoCggEBAJ10aK/cLN4sIYJoL9ObdSxez0brLJSnpJvht1nu9pYbQJ3KZtAz\n"
"OQ8D3QoILUsUI+SSM3bJMGLtwzZqSVKpU6ciVlAnLkogLdAsKCK2TFB4l3Uqa2MD\n"
"NUXqT6ezTRg5DjSJ/SGSRU0uIRZaFYBPrWe5b926FdEwmP3aqHOyrJToQOdwNwmw\n"
"N8G2tY3V5CPl6uwbqBrPhrPXsM8kcD3AnrefM7KGv0hR4Rwra4udIzPpxVzytH2x\n"
"qzxA5rLufbl/NWLLO8QM5tAwrbYv4zCIjzKPgEI9Pb8Gx/qo65xHrOR33tRHz87r\n"
"ZhWltG788FXAZyKmDHeXu8onthwscqoIO40CAwEAAaNaMFgwCQYDVR0TBAIwADAL\n"
"BgNVHQ8EBAMCBeAwHQYDVR0OBBYEFNCx8F06FN4a8+duXFRi2l/xHIU4MB8GA1Ud\n"
"IwQYMBaAFA2CvxOKeGVoIPLLySJOpnlqUlgfMA0GCSqGSIb3DQEBCwUAA4IBAQBy\n"
"km7QLiqz6icijns0vu6h3ycxPVfjMFfTOF+nnQA7DVtaSqFswF+Ee6oS3WEzK50p\n"
"J7/MVWqIEY+u/3/pdmxbh/fc/+VfFGkSG8MXin2fzEgUFuG7pgVpP8bYIW1NWyN8\n"
"4DqOycKECE1BfGz67Z6kY3yZFdep9573klqfM8BLGzYPJOlrdLZcxKHvD7evomQk\n"
"+iGtFZJl1/hBX9/Sqs7irbn4qNtsux2lTJMdt72goDeQA3nHWaErL3yJWG8hfTMh\n"
"hf9D5XZdxs6FD1W2WYiME5ssU7QKjLb3iCNwJH/0sdIJphW6ngSzMKNSBdsNZ0aV\n"
"RMXkP7i3EkHhitvL2Kj7\n"
"-----END CERTIFICATE-----";

const char *RSA_DEVICE_CERT = "-----BEGIN CERTIFICATE-----\n"
"MIIDdzCCAl+gAwIBAgIFAt/cGLIwDQYJKoZIhvcNAQELBQAwSzEPMA0GA1UECgwG\n"
"VEVTVCBYMSswKQYDVQQDDCJURVNUIFggUlNBIERldmljZSBBdHRlc3RhdGlvbiBD\n"
"QSAxMQswCQYDVQQGEwJDTjAeFw0yNTA2MDcwNzA5MzBaFw00NTA0MDMwNzA5MzBa\n"
"ME0xDzANBgNVBAoMBlRFU1QgWDEtMCsGA1UEAwwkVEVTVCBYIFJTQSBEZXZpY2Ug\n"
"QXR0ZXN0YXRpb24gREVWSUNFMQswCQYDVQQGEwJDTjCCASIwDQYJKoZIhvcNAQEB\n"
"BQADggEPADCCAQoCggEBANOsuN3tcgiaGFZmwNzBMfMZi67ZFxY1I5D75Qajwrmt\n"
"yAo5R/NMPucVMrvckd1IsDHN7UQcPIvmJ7ldGPOlS6SEzLpStK8umhwzFtPm7D60\n"
"Z8pvAmdlkVzL2zjgMHFpBHfxHv+8jQmsjp97NpKHDka4PMJyzde66GlnttHKcgl0\n"
"BTF8oCJaIxFjdkQJo9ysDGGPzdf2kup7Wtw2hx85pW+1pkdTds4T26ana9lAUyZ7\n"
"TU7wwTYhVRA66q3glsUe00VS42oVHEdMLQ7/OttcPYykdxXnB8S0UpMRm8+lv5AK\n"
"RV8oZNLEiLhoGlYuhedrER9PJzwa9fDAgMRoAoqpS/8CAwEAAaNgMF4wHQYDVR0O\n"
"BBYEFA2CvxOKeGVoIPLLySJOpnlqUlgfMB8GA1UdIwQYMBaAFHHvU7ekzs8s7dmC\n"
"kxSnj0xYpwJCMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3\n"
"DQEBCwUAA4IBAQBATEYG/J99XumDMNNpacz/HGSAvR9iu9yb0lRZEMvZKPd56Z/U\n"
"fPxBZPiXIDJLvK36skkhLLaHL4Op6dWYIC2Jp8SjfrsfIpyylxwkEh0Gtbs/+NFt\n"
"53E4QtcNilFDQ17wcuKv0UVQCG3DlgzaS9jdyrQ2C4/zwOnC/vQD5tUvXJUFaQel\n"
"PbQth4+amxl1pHQA7XSBKHvL9hWalRJEUOsKnwAAGwcZgmWQyyqDv9eosab68Kvw\n"
"PaNXdE5awQRtlfNj4xTfXqkNye9q4QuxqjEB4gW5UKv9OTld1kWM7rgRAKOSNPvX\n"
"OQGMH1BpjHLmYtZgrqhuZ/4zZgj0Zpq99dzo\n"
"-----END CERTIFICATE-----";

const char *RSA_SUB_CA_CERT = "-----BEGIN CERTIFICATE-----\n"
"MIIDbTCCAlWgAwIBAgIFAt/cGLIwDQYJKoZIhvcNAQELBQAwQzEPMA0GA1UECgwG\n"
"VEVTVCBYMTAwLgYDVQQDDCdURVNUIFggUlNBIERldmljZSBBdHRlc3RhdGlvbiBS\n"
"b290IENBIDEwHhcNMjUwNjA3MDcwOTMwWhcNNDUwNDAzMDcwOTMwWjBLMQ8wDQYD\n"
"VQQKDAZURVNUIFgxKzApBgNVBAMMIlRFU1QgWCBSU0EgRGV2aWNlIEF0dGVzdGF0\n"
"aW9uIENBIDExCzAJBgNVBAYTAkNOMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
"CgKCAQEAlr25YgexwMxxZ8qNL2+kIbkE5Hb1uXJvIGkSw5T3jz8ux4atgJY7uX7X\n"
"eiXOmSf7FQZJBHwB8YZRXUyXuDqr1rCPa+OFN+Nq4i0xr68oIfaCxNPF758Nd5m2\n"
"fWR62bNha3s14NlP2XGAcX0xxiVRYYDu/Onqp3L+JfwM5a+JMED8TMfha7YBqRV0\n"
"1uVPPKokuClLS8qbKZW5KCTkC64UX3hhBsAZW6LFESIn710mWje9iqQgOyxnj7QE\n"
"DIvhtGwITNCk9QHN6u8ZZILJpLzlr7Fw/2viPw7tBJvtIvXQ9TqXdYZZLCrpCW3m\n"
"CnjWku/XNQcafoN52LmS8RN8zeLPwQIDAQABo2AwXjAdBgNVHQ4EFgQUce9Tt6TO\n"
"zyzt2YKTFKePTFinAkIwHwYDVR0jBBgwFoAUFsQBWxIPsSg5wN8KowiyehKaNzcw\n"
"DwYDVR0TAQH/BAUwAwEB/zALBgNVHQ8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEB\n"
"AEVAKVjptSLKIE4CNl8BleRRi+1lQz0d3PZljrGpUs5fZoNuCxQHys4wsb8lOeBI\n"
"OOEQlv4aKov2Rvc98CMtGq5h16J3X4JqRgFVrdlAO1TzIVz2/L0AhuEw+nY5R5la\n"
"8i8qZowlqEJ/QpmDqHOkrt7MpsTR0+79hBuXzTUkhClqy/WTH/k4T0v233Anf7gm\n"
"MLlS2b7TWAgNSOdqKrVz8BCIuSOUoH4X5PKCQOUISI7tepVm+krNjYTnUAa7SEJ6\n"
"ZcQs3ZUk5dH1XneYDU5ST/py/pwYGx3+wlmWkkebVkl4BwdAlSe7ijQlkiFkg+8S\n"
"fvSxx0+k1nQrvNGuu91+le4=\n"
"-----END CERTIFICATE-----";

string g_cn1 = "TEST X ECC Device Attestation CA";
string g_o = "TEST X";
string g_c = "CN";
string g_cn2 = "TEST X RSA Device Attestation CA";

const static CertSnInfo SUB_CA_SUBJECT_INFO[] = {
    {const_cast<char *>(g_cn1.c_str()), nullptr, const_cast<char *>(g_o.c_str()), const_cast<char *>(g_c.c_str())},
    {const_cast<char *>(g_cn2.c_str()), nullptr, const_cast<char *>(g_o.c_str()), const_cast<char *>(g_c.c_str())},
};

#define SUB_CA_SUBJECT_INFO_LEN 2

string g_cn3 = "XXXX";
const static CertSnInfo SUB_CA_SUBJECT_INFO_ERROR[] = {
    {const_cast<char *>(g_cn3.c_str()), nullptr, nullptr, nullptr},
};

void BaseTest(HcfAttestCertVerifyParam *param, char *certs)
{
    CfEncodingBlob data = {0};
    data.encodingFormat = CF_FORMAT_PEM;
    data.data = reinterpret_cast<uint8_t *>(certs);
    data.len = strlen(certs);
    HmAttestationInfo *info = nullptr;
    CfResult ret = HcfAttestCertVerify(&data, param, &info);
    ASSERT_EQ(ret, CF_SUCCESS);

    ret = HcfAttestCertParseExtension(info);
    ASSERT_EQ(ret, CF_SUCCESS);

    ret = HcfAttestCheckBoundedWithUdId(info);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);

    ret = HcfAttestCheckBoundedWithSocid(info);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);

    HmAttestationCertExt ext = { 0 };
    ret = HcfAttestGetCertExtension(info, DEVICE_ACTIVATION_DEVICE_ID1, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = HcfAttestGetCertExtension(info, ATTESTATION_ENC_PADDING, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = HcfAttestGetCertExtension(info, ATTESTATION_CERT_EXT_TYPE_MAX, &ext);
    ASSERT_EQ(ret, CF_ERR_PARAMETER_CHECK);

    ret = HcfAttestGetCertExtension(info, LEGACY_VERSION, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = HcfAttestGetCertExtension(info, KM_TAG_TYPE_MAX, &ext);
    ASSERT_EQ(ret, CF_ERR_PARAMETER_CHECK);
    HcfAttestInfoFree(info);
}

static int CreateCertChain(const char *certs[], int num, char **chain)
{
    int i = 0;
    size_t len = 0;
    for (i = 0; i < num; i++) {
        len += strlen(certs[i]);
    }

    len += num;
    char *out = reinterpret_cast<char *>(CfMalloc(len + 1, 0));
    if (out == nullptr) {
        return -1;
    }

    for (i = 0; i < num; i++) {
        if (memcpy_s(out + strlen(out), len - strlen(out), certs[i], strlen(certs[i])) != EOK) {
            CfFree(out);
            return -1;
        }
        void *src = reinterpret_cast<void *>(const_cast<char *>("\n"));
        if (memcpy_s(out + strlen(out), len - strlen(out), src, 1) != EOK) {
            CfFree(out);
            return -1;
        }
    }
    *chain = out;
    return 0;
}

/**
 * @tc.name: CfAttestationTest001
 * @tc.desc: attestation cert verify and parse
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(CfAttestationTest, CfAttestationTest001, TestSize.Level0)
{
    HcfAttestCertVerifyParam *param = nullptr;
    CfResult ret = HcfAttestCreateVerifyParam(&param);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = HcfAttestSetVerifyParamCheckTime(param, true);
    ASSERT_EQ(ret, CF_SUCCESS);
    CfEncodingBlob rootCa = {0};
    rootCa.encodingFormat = CF_FORMAT_PEM;
    rootCa.data = reinterpret_cast<uint8_t *>(const_cast<char *>(EC_ROOT_CA));
    rootCa.len = strlen(EC_ROOT_CA);
    ret = HcfAttestSetVerifyParamRootCa(param, &rootCa);
    ASSERT_EQ(ret, CF_SUCCESS);

    HmAttestationSnInfo snInfos = { 0 };
    snInfos.certSnInfos = const_cast<CertSnInfo *>(&SUB_CA_SUBJECT_INFO[0]);
    snInfos.num = SUB_CA_SUBJECT_INFO_LEN;
    ret = HcfAttestSetVerifyParamSnInfos(param, &snInfos);
    ASSERT_EQ(ret, CF_SUCCESS);

    char *chain = nullptr;
    const char *certs[] = {EC_APP_CERT, EC_DEVICE_CERT, EC_SUB_CA_CERT};
    int num = sizeof(certs) / sizeof(certs[0]);
    int res = CreateCertChain(certs, num, &chain);
    ASSERT_EQ(res, 0);
    BaseTest(param, chain);
    HcfAttestFreeVerifyParam(param);
    CfFree(chain);
}

/**
 * @tc.name: CfAttestationTest002
 * @tc.desc: attestation cert verify and parse
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(CfAttestationTest, CfAttestationTest002, TestSize.Level0)
{
    HcfAttestCertVerifyParam *param = nullptr;
    CfResult ret = HcfAttestCreateVerifyParam(&param);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = HcfAttestSetVerifyParamCheckTime(param, false);
    ASSERT_EQ(ret, CF_SUCCESS);
    CfEncodingBlob rootCa = {0};
    rootCa.encodingFormat = CF_FORMAT_PEM;
    rootCa.data = reinterpret_cast<uint8_t *>(const_cast<char *>(RSA_ROOT_CA));
    rootCa.len = strlen(RSA_ROOT_CA);
    ret = HcfAttestSetVerifyParamRootCa(param, &rootCa);
    ASSERT_EQ(ret, CF_SUCCESS);

    HmAttestationSnInfo snInfos = { 0 };
    snInfos.certSnInfos = const_cast<CertSnInfo *>(&SUB_CA_SUBJECT_INFO[0]);
    snInfos.num = SUB_CA_SUBJECT_INFO_LEN;
    ret = HcfAttestSetVerifyParamSnInfos(param, &snInfos);
    ASSERT_EQ(ret, CF_SUCCESS);

    char *chain = nullptr;
    const char *certs[] = {RSA_APP_CERT, RSA_DEVICE_CERT, RSA_SUB_CA_CERT};
    int num = sizeof(certs) / sizeof(certs[0]);
    int res = CreateCertChain(certs, num, &chain);
    ASSERT_EQ(res, 0);
    BaseTest(param, chain);
    HcfAttestFreeVerifyParam(param);
    CfFree(chain);
}

/**
 * @tc.name: CfAttestationTest003
 * @tc.desc: attestation cert verify sn failed
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(CfAttestationTest, CfAttestationTest003, TestSize.Level0)
{
    HcfAttestCertVerifyParam *param = nullptr;
    CfResult ret = HcfAttestCreateVerifyParam(&param);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfEncodingBlob rootCa = {0};
    rootCa.encodingFormat = CF_FORMAT_PEM;
    rootCa.data = reinterpret_cast<uint8_t *>(const_cast<char *>(EC_ROOT_CA));
    rootCa.len = strlen(EC_ROOT_CA);
    ret = HcfAttestSetVerifyParamRootCa(param, &rootCa);
    ASSERT_EQ(ret, CF_SUCCESS);

    HmAttestationSnInfo snInfos = { 0 };
    snInfos.certSnInfos = const_cast<CertSnInfo *>(&SUB_CA_SUBJECT_INFO_ERROR[0]);
    snInfos.num = 1;
    ret = HcfAttestSetVerifyParamSnInfos(param, &snInfos);
    ASSERT_EQ(ret, CF_SUCCESS);

    char *chain = nullptr;
    const char *certs[] = {EC_APP_CERT, EC_DEVICE_CERT, EC_SUB_CA_CERT};
    int num = sizeof(certs) / sizeof(certs[0]);
    int res = CreateCertChain(certs, num, &chain);
    ASSERT_EQ(res, 0);
    CfEncodingBlob certsChain = {0};
    certsChain.encodingFormat = CF_FORMAT_PEM;
    certsChain.data = reinterpret_cast<uint8_t *>(chain);
    certsChain.len = strlen(chain);
    HmAttestationInfo *info = nullptr;
    ret= HcfAttestCertVerify(&certsChain, param, &info);
    ASSERT_EQ(ret, CF_ERR_PARAMETER_CHECK);

    HcfAttestFreeVerifyParam(param);
    CfFree(chain);
}

/**
 * @tc.name: CfAttestationTest004
 * @tc.desc: attestation cert verify failed
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(CfAttestationTest, CfAttestationTest004, TestSize.Level0)
{
    HcfAttestCertVerifyParam *param = nullptr;
    CfResult ret = HcfAttestCreateVerifyParam(&param);
    ASSERT_EQ(ret, CF_SUCCESS);

    HmAttestationSnInfo snInfos = { 0 };
    snInfos.certSnInfos = const_cast<CertSnInfo *>(&SUB_CA_SUBJECT_INFO[0]);
    snInfos.num = SUB_CA_SUBJECT_INFO_LEN;
    ret = HcfAttestSetVerifyParamSnInfos(param, &snInfos);
    ASSERT_EQ(ret, CF_SUCCESS);

    char *chain = nullptr;
    const char *certs[] = {EC_APP_CERT, EC_DEVICE_CERT, EC_SUB_CA_CERT};
    int num = sizeof(certs) / sizeof(certs[0]);
    int res = CreateCertChain(certs, num, &chain);
    ASSERT_EQ(res, 0);
    CfEncodingBlob certsChain = {0};
    certsChain.encodingFormat = CF_FORMAT_PEM;
    certsChain.data = reinterpret_cast<uint8_t *>(chain);
    certsChain.len = strlen(chain);
    HmAttestationInfo *info = nullptr;
    ret= HcfAttestCertVerify(&certsChain, param, &info);
    ASSERT_EQ(ret, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    HcfAttestFreeVerifyParam(param);
    CfFree(chain);
}

/**
 * @tc.name: CfAttestationTest005
 * @tc.desc: attestation cert verify failed
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(CfAttestationTest, CfAttestationTest005, TestSize.Level0)
{
    HcfAttestCertVerifyParam *param = nullptr;
    CfResult ret = HcfAttestCreateVerifyParam(&param);
    ASSERT_EQ(ret, CF_SUCCESS);

    CfEncodingBlob rootCa = {0};
    rootCa.encodingFormat = CF_FORMAT_PEM;
    rootCa.data = reinterpret_cast<uint8_t *>(const_cast<char *>(EC_ROOT_CA));
    rootCa.len = strlen(EC_ROOT_CA);
    ret = HcfAttestSetVerifyParamRootCa(param, &rootCa);
    ASSERT_EQ(ret, CF_SUCCESS);

    HmAttestationSnInfo snInfos = { 0 };
    snInfos.certSnInfos = const_cast<CertSnInfo *>(&SUB_CA_SUBJECT_INFO[0]);
    snInfos.num = SUB_CA_SUBJECT_INFO_LEN;
    ret = HcfAttestSetVerifyParamSnInfos(param, &snInfos);
    ASSERT_EQ(ret, CF_SUCCESS);

    char *chain = nullptr;
    const char *certs[] = {EC_APP_CERT, EC_SUB_CA_CERT, EC_DEVICE_CERT};
    int num = sizeof(certs) / sizeof(certs[0]);
    int res = CreateCertChain(certs, num, &chain);
    ASSERT_EQ(res, 0);
    CfEncodingBlob certsChain = {0};
    certsChain.encodingFormat = CF_FORMAT_PEM;
    certsChain.data = reinterpret_cast<uint8_t *>(chain);
    certsChain.len = strlen(chain);
    HmAttestationInfo *info = nullptr;
    ret= HcfAttestCertVerify(&certsChain, param, &info);
    ASSERT_EQ(ret, CF_ERR_PARAMETER_CHECK);

    HcfAttestFreeVerifyParam(param);
    CfFree(chain);
}

/**
 * @tc.name: CfAttestationTest006
 * @tc.desc: nullptr param
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(CfAttestationTest, CfAttestationTest006, TestSize.Level0)
{
    CfResult ret = HcfAttestCreateVerifyParam(nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    ret = HcfAttestSetVerifyParamRootCa(nullptr, nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    ret = HcfAttestSetVerifyParamSnInfos(nullptr, nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    ret= HcfAttestCertVerify(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    HcfAttestFreeVerifyParam(nullptr);

    ret = HcfAttestCertParseExtension(nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    ret = HcfAttestCheckBoundedWithUdId(nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    ret = HcfAttestCheckBoundedWithSocid(nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    ret = GetHmKeyDescription(nullptr, nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    FreeHmKeyDescription(nullptr);

    ret = GetKeyDescriptionExt(nullptr, KM_TAG_ATTESTATION_ID_UDID, nullptr);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);

    ret = GetHmAttestationRecord(nullptr, nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);
    ret = GetDeviceCertSecureLevel(nullptr, nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);
    ret = GetDeviceActivationCertExt(nullptr, nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    ret = GetDeviceSecureLevel(nullptr, nullptr, nullptr);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);

    ret = GetAttestCertExt(nullptr, KM_TAG_ATTESTATION_ID_SOCID, nullptr);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);

    FreeHmAttestationRecord(nullptr);
    FreeAttestationDevSecLevel(nullptr);
    FreeDeviveActiveCertExt(nullptr);

    bool res = CmpObjOid(nullptr, nullptr, 0);
    ASSERT_EQ(res, false);

    ret = FindCertExt(nullptr, nullptr, 0, nullptr);
    ASSERT_EQ(ret, CF_NULL_POINTER);

    ret = GetOctectOrUtf8Data(nullptr, nullptr);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
}

/**
 * @tc.name: CfAttestationTest007
 * @tc.desc: FindCertExt test
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(CfAttestationTest, CfAttestationTest007, TestSize.Level0)
{
    BIO *bio = BIO_new_mem_buf(RSA_APP_CERT, -1);
    ASSERT_NE(bio, nullptr);
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    ASSERT_NE(cert, nullptr);
    const uint8_t oid[] = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x01};
    X509_EXTENSION *extension = nullptr;
    CfResult ret = FindCertExt(cert, oid, sizeof(oid) / sizeof(uint8_t), &extension);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);

    const uint8_t keyUsageOid[] = {0x55, 0x1D, 0x0F};
    ret = FindCertExt(cert, keyUsageOid, sizeof(keyUsageOid) / sizeof(uint8_t), &extension);
    ASSERT_EQ(ret, CF_SUCCESS);
    X509_free(cert);
}

const char *EC_CERT = "-----BEGIN CERTIFICATE-----\n"
"MIICqTCCAk+gAwIBAgIBATAKBggqhkjOPQQDAjBvMQswCQYDVQ\n"
"QGEwJDTjEPMA0GA1UECgwGSHVhd2VpMRMwEQYDVQQLDApIdWF3\n"
"ZWkgQ0JHMTowOAYDVQQDDDFIVUFXRUlfRFVNTVlfY2UyMzkxMT\n"
"AtYmE3Yy00MTgzLWEyMWItMWQzZmVlMWJmODAxMB4XDTI0MDcz\n"
"MDA4MDU0OFoXDTM0MDczMDA4MDU0OFowLDEqMCgGA1UEAxMhRG\n"
"V2aWNlIENlcnRpZmljYXRlIE1hbmFnZW1lbnQgS2V5MFkwEwYH\n"
"KoZIzj0CAQYIKoZIzj0DAQcDQgAE/dEvnvemtQcef2qD2vrzPc\n"
"5mg1cLZtr/sJ2+Yl7TqYwXfKxy7kmttZEcVO86EbN7VqYnp3BO\n"
"KiRtxjQvvWF+mKOCAR0wggEZMAsGA1UdDwQEAwIHgDAIBgNVHR\n"
"8EAQAwgf8GDCsGAQQBj1sCgngBAwSB7jCB6wIBADA0AgEABg0r\n"
"BgEEAY9bAoJ4AgEEBCAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFh\n"
"cYGRobHB0eHzAcAgEDBg4rBgEEAY9bAoJ4AgIECgwHSURfVURJ\n"
"RDAdAgEDBg4rBgEEAY9bAoJ4AgIECQwISURfU09DSUQwHAIBAw\n"
"YOKwYBBAGPWwKCeAICBAEMB0lEX0lNRUkwHgIBAwYOKwYBBAGP\n"
"WwKCeAICBAMMCUlEX1NFUklBTDA1AgEDBg4rBgEEAY9bAoJ4Ag\n"
"ICCQQgbm5sYGE1NjAICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8w\n"
"CgYIKoZIzj0EAwIDSAAwRQIgflpGB+qDfK+0/sas+nFXzV4RS3\n"
"np+XpdrUQoDRqjQQACIQC6aPfMdND3VP3n/3BYDjatM0ZI9ms2\n"
"UHiE7qDAqjDGRw==\n"
"-----END CERTIFICATE-----";

const char *RSA_CERT = "-----BEGIN CERTIFICATE-----\n"
"MIID8zCCA5egAwIBAgIBATAMBggqhkjOPQQDAgUAMC8xGTAXBgNVBAUTEDY5N2Jj\n"
"NjRiNmNkNGMwMWUxEjAQBgNVBAwMCVN0cm9uZ0JveDAeFw03MDAxMDEwMDAwMDBa\n"
"Fw0yODA1MjMyMzU5NTlaMB8xHTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECstYocmJbek7v23h3GMNnK7dU3fC\n"
"UstHmvOWiV63ueF0duOMAn44jo/yzPT7UKoaAy8Q4KMEUUTAtPI/8M6YzKOCArAw\n"
"ggKsMA4GA1UdDwEB/wQEAwIHgDCCApgGCisGAQQB1nkCAREEggKIMIIChAIBAwoB\n"
"AgIBBAoBAgQDYWJjBAAwggHNv4U9CAIGAWt5u/FKv4VFggG7BIIBtzCCAbMxggGL\n"
"MAwEB2FuZHJvaWQCAR0wGQQUY29tLmFuZHJvaWQua2V5Y2hhaW4CAR0wGQQUY29t\n"
"LmFuZHJvaWQuc2V0dGluZ3MCAR0wGQQUY29tLnF0aS5kaWFnc2VydmljZXMCAR0w\n"
"GgQVY29tLmFuZHJvaWQuZHluc3lzdGVtAgEdMB0EGGNvbS5hbmRyb2lkLmlucHV0\n"
"ZGV2aWNlcwIBHTAfBBpjb20uYW5kcm9pZC5sb2NhbHRyYW5zcG9ydAIBHTAfBBpj\n"
"b20uYW5kcm9pZC5sb2NhdGlvbi5mdXNlZAIBHTAfBBpjb20uYW5kcm9pZC5zZXJ2\n"
"ZXIudGVsZWNvbQIBHTAgBBtjb20uYW5kcm9pZC53YWxscGFwZXJiYWNrdXACAR0w\n"
"IQQcY29tLmdvb2dsZS5TU1Jlc3RhcnREZXRlY3RvcgIBHTAiBB1jb20uZ29vZ2xl\n"
"LmFuZHJvaWQuaGlkZGVubWVudQIBATAjBB5jb20uYW5kcm9pZC5wcm92aWRlcnMu\n"
"c2V0dGluZ3MCAR0xIgQgMBqjywgRNFAcRfFCKrxmwkIk/V3tX9yPF+aXF2/YZqow\n"
"gZ2hCDEGAgECAgEDogMCAQOjBAICAQClBTEDAgEEv4N3AgUAv4U+AwIBAL+FQEww\n"
"SgQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQAKAQIEIHKNsSdP\n"
"HxzxVx3kOAsEilVKxKOA529TVQg1KQhKk3gBv4VBAwIBAL+FQgUCAwMUs7+FTgYC\n"
"BAE0FfG/hU8GAgQBNBXsMAwGCCqGSM49BAMCBQADSAAwRQIgKYHTtsFSBwKkCelW\n"
"n0/SlsYZSQm9MWafyTO+uFblMHMCIQCvw4IiiEajx6WqDPPAnZO4NyKAj5tElqdD\n"
"FPaMKikScg==\n"
"-----END CERTIFICATE-----";

static void TestGetAttestCertExt(AttestationRecord *record)
{
    CfResult ret;
    HmAttestationCertExt ext = {0};
    ret = GetAttestCertExt(record, ATTESTATION_KEY_PURPOSE, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_APP_ID_HAP_ID, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_APP_ID_SA_ID, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_APP_ID_UNIFIED_ID, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_APP_ID_UNIFIED_ID, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_CHALLENGE, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetAttestCertExt(record, ATTESTATION_KEY_FLAG, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_DIGEST, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_ENC_PADDING, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_SIGN_TYPE, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_VERSION_INFO, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_PURPOSE, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_ID_PADDING_FLAG, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_NONCE, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetAttestCertExt(record, ATTESTATION_IMEI, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetAttestCertExt(record, ATTESTATION_SERIAL, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetAttestCertExt(record, ATTESTATION_MEID, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_MODEL, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetAttestCertExt(record, ATTESTATION_SOCID, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetAttestCertExt(record, ATTESTATION_UDID, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetAttestCertExt(record, ATTESTATION_VERSION, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
}

/**
 * @tc.name: CfAttestationTest008
 * @tc.desc: GetHmAttestationRecord ec test
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(CfAttestationTest, CfAttestationTest008, TestSize.Level0)
{
    BIO *bio = BIO_new_mem_buf(EC_CERT, -1);
    ASSERT_NE(bio, nullptr);
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    ASSERT_NE(cert, nullptr);

    AttestationRecord *record = nullptr;
    CfResult ret = GetHmAttestationRecord(cert, &record);
    ASSERT_EQ(ret, CF_SUCCESS);
    TestGetAttestCertExt(record);
    FreeHmAttestationRecord(record);
    X509_free(cert);
}

static void TestGetKeyDescriptionBase(LegacyKeyDescription *record)
{
    CfResult ret;
    HmAttestationCertExt ext = {0};
    ret = GetKeyDescriptionExt(record, LEGACY_VERSION, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, LEGACY_SECURITY_LEVEL, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, LEGACY_KM_VERSION, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, LEGACY_KM_SECURITY_LEVEL, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, LEGACY_CHALLENGE, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, LEGACY_UNIQUE_ID, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
}

static void TestGetHmKeyDescription(LegacyKeyDescription *record)
{
    CfResult ret;
    HmAttestationCertExt ext = {0};
    ret = GetKeyDescriptionExt(record, KM_TAG_PURPOSE, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, KM_TAG_ALGORITHM, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, KM_TAG_KEY_SIZE, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, KM_TAG_KEY_DIGEST, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, KM_TAG_KEY_PADDING, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_EC_CURVE, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_RSA_PUBLIC_EXPONENT, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_NO_AUTH_REQUIRED, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, KM_TAG_USER_AUTH_TYPE, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_CREATION_DATETIME, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_ORIGIN, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, KM_TAG_OS_VERSION, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, KM_TAG_OS_PATCH_LEVEL, &ext);
    ASSERT_EQ(ret, CF_SUCCESS);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_BRAND, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_DEVICE, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_PRODUCT, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_SERIAL, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_IMEI, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_MEID, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_MANUFACTURER, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_MODEL, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_SOCID, &ext); // integer
    ASSERT_EQ(ret, CF_ERR_INVALID_EXTENSION);
    ret = GetKeyDescriptionExt(record, KM_TAG_ATTESTATION_ID_UDID, &ext);
    ASSERT_EQ(ret, CF_ERR_EXTENSION_NOT_EXIST);
}

/**
 * @tc.name: CfAttestationTest009
 * @tc.desc: GetHmAttestationRecord rsa test
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(CfAttestationTest, CfAttestationTest009, TestSize.Level0)
{
    BIO *bio = BIO_new_mem_buf(RSA_CERT, -1);
    ASSERT_NE(bio, nullptr);
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    ASSERT_NE(cert, nullptr);

    LegacyKeyDescription *record = nullptr;
    CfResult ret = GetHmKeyDescription(cert, &record);
    ASSERT_EQ(ret, CF_SUCCESS);
    TestGetKeyDescriptionBase(record);
    TestGetHmKeyDescription(record);
    FreeHmKeyDescription(record);
    X509_free(cert);
}
} // namespace
