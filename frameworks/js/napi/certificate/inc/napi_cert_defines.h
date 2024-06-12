/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef NAPI_CERT_DEFINES_H
#define NAPI_CERT_DEFINES_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace CertFramework {
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr size_t ARGS_SIZE_FOUR = 4;
constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;
constexpr uint32_t BYTE_TO_BIT_CNT = 8;
constexpr uint32_t QUAD_WORD_ALIGN_UP = 3;
constexpr uint32_t MAX_LEN_OF_ARRAY = 1024;

const std::string CERT_TAG_DATA = "data";
const std::string CERT_TAG_ERR_CODE = "code";
const std::string CERT_TAG_COUNT = "count";
const std::string CERT_TAG_ENCODING_FORMAT = "encodingFormat";
const std::string CERT_TAG_ALGORITHM = "algorithm";
const std::string CRYPTO_TAG_ALG_NAME = "algName";
const std::string CRYPTO_TAG_FORMAT = "format";
const std::string CERT_TAG_CERT_COLLECTION = "certCollection";
const std::string CERT_TAG_CERT_MATCH_PARAMS = "certMatchParameters";
const std::string CERT_TAG_MAX_LENGTH = "maxLength";
const std::string CERT_TAG_VALIDATE_PARAMS = "validationParameters";
const std::string CERT_TAG_KEYSTORE = "keystore";

enum ResultCode {
    JS_SUCCESS = 0,
    JS_ERR_CERT_INVALID_PARAMS = 401,
    JS_ERR_CERT_NOT_SUPPORT = 801,
    JS_ERR_CERT_OUT_OF_MEMORY = 19020001,
    JS_ERR_CERT_RUNTIME_ERROR = 19020002,
    JS_ERR_CERT_CRYPTO_OPERATION = 19030001,
    JS_ERR_CERT_SIGNATURE_FAILURE = 19030002,
    JS_ERR_CERT_NOT_YET_VALID = 19030003,
    JS_ERR_CERT_HAS_EXPIRED = 19030004,
    JS_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 19030005,
    JS_ERR_KEYUSAGE_NO_CERTSIGN = 19030006,
    JS_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 19030007
};

enum AsyncType { ASYNC_TYPE_CALLBACK = 1, ASYNC_TYPE_PROMISE = 2 };
// X509 CERT MATCH PARAMETERS
const std::string CERT_MATCH_TAG_SUBJECT_ALT_NAMES_TYPE = "type";
const std::string CERT_MATCH_TAG_SUBJECT_ALT_NAMES_DATA = "name";
const std::string CERT_MATCH_TAG_SUBJECT_ALT_NAMES = "subjectAlternativeNames";
const std::string CERT_MATCH_TAG_MATCH_ALL_SUBJECT = "matchAllSubjectAltNames";
const std::string CERT_MATCH_TAG_AUTH_KEY_ID = "authorityKeyIdentifier";
const std::string CERT_MATCH_TAG_MIN_PATH_LEN = "minPathLenConstraint";
const std::string CERT_MATCH_TAG_X509CERT = "x509Cert";
const std::string CERT_MATCH_TAG_VALID_DATE = "validDate";
const std::string CERT_MATCH_TAG_ISSUER = "issuer";
const std::string CERT_MATCH_TAG_EXTENDED_KEY_USAGE = "extendedKeyUsage";
const std::string CERT_MATCH_TAG_KEY_USAGE = "keyUsage";
const std::string CERT_MATCH_TAG_NAME_CONSTRAINTS = "nameConstraints";
const std::string CERT_MATCH_TAG_CERT_POLICY = "certPolicy";
const std::string CERT_MATCH_TAG_PRIVATE_KEY_VALID = "privateKeyValid";
const std::string CERT_MATCH_TAG_SERIAL_NUMBER = "serialNumber";
const std::string CERT_MATCH_TAG_SUBJECT = "subject";
const std::string CERT_MATCH_TAG_SUBJECT_KEY_IDENTIFIER = "subjectKeyIdentifier";
const std::string CERT_MATCH_TAG_PUBLIC_KEY = "publicKey";
const std::string CERT_MATCH_TAG_PUBLIC_KEY_ALGID = "publicKeyAlgID";

// X509 CRL MATCH PARAMETERS
const std::string CRL_MATCH_TAG_PRIVATE_KEY_VALID = "issuer";
const std::string CRL_MATCH_TAG_X509CERT = "x509Cert";
const std::string CRL_MATCH_TAG_UPDATE_DATE_TIME = "updateDateTime";
const std::string CRL_MATCH_TAG_MAXCRL = "maxCRL";
const std::string CRL_MATCH_TAG_MINCRL = "minCRL";

// X509 CERT CHAIN VALIDATE
// X509TrustAnchor
const std::string CERT_CHAIN_TRUSTANCHOR_TAG_CACERT = "CACert";
const std::string CERT_CHAIN_TRUSTANCHOR_TAG_CAPUBKEY = "CAPubKey";
// const std::string CERT_CHAIN_TRUSTANCHOR_TAG_NAMECSTRAINTS = "nameConstraints";
const std::string CERT_CHAIN_TRUSTANCHOR_TAG_CASUBJECT = "CASubject";
// CertChainValidateParameters
const std::string CERT_CHAIN_VALIDATE_TAG_DATE = "date";
const std::string CERT_CHAIN_VALIDATE_TAG_TRUSTANCHORS = "trustAnchors";
const std::string CERT_CHAIN_VALIDATE_TAG_CERTCRLS = "certCRLs";
const std::string CERT_CHAIN_VALIDATE_TAG_REVOCATIONCHECKPARAM = "revocationCheckParam";
const std::string CERT_CHAIN_VALIDATE_TAG_OCSP_REQ_EXTENSION = "ocspRequestExtension";
const std::string CERT_CHAIN_VALIDATE_TAG_OCSP_RESP_URI = "ocspResponderURI";
const std::string CERT_CHAIN_VALIDATE_TAG_OCSP_RESP_CERT = "ocspResponderCert";
const std::string CERT_CHAIN_VALIDATE_TAG_OCSP_RESPS = "ocspResponses";
const std::string CERT_CHAIN_VALIDATE_TAG_CRL_DOWNLOAD_URI = "crlDownloadURI";
const std::string CERT_CHAIN_VALIDATE_TAG_OPTIONS = "options";
const std::string CERT_CHAIN_VALIDATE_TAG_OCSP_DIGEST = "ocspDigest";
const std::string CERT_CHAIN_VALIDATE_TAG_POLICY = "policy";
const std::string CERT_CHAIN_VALIDATE_TAG_SSLHOSTNAME = "sslHostname";
const std::string CERT_CHAIN_VALIDATE_TAG_KEYUSAGE = "keyUsage";
// CertChainValidateResult
const std::string CERT_CHAIN_VALIDATE_RESULLT_TAG_TRUSTANCHOR = "trustAnchor";
const std::string CERT_CHAIN_VALIDATE_RESULLT_TAG_X509CERT = "entityCert";

const std::string CERT_CHAIN_BUILD_RESULLT_TAG_CERTCHAIN = "certChain";
const std::string CERT_CHAIN_BUILD_RESULLT_TAG_VALIDATERESULT = "validationResult";

} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_CERT_DEFINES_H
