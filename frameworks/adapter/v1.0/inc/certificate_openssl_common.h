/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef CF_CERTIFICATE_OPENSSL_COMMON_H
#define CF_CERTIFICATE_OPENSSL_COMMON_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdint.h>

#include "cf_blob.h"
#include "cf_result.h"
#include "x509_cert_match_parameters.h"
#include "x509_distinguished_name_spi.h"
#include "x509_cert_chain_validate_params.h"

#define CF_OPENSSL_SUCCESS 1 /* openssl return 1: success */
#define OID_STR_MAX_LEN 128
#define CHAR_TO_BIT_LEN 8
#define MAX_DATE_STR_LEN 128
#define FLAG_BIT_LEFT_NUM 0x07
#define DATETIME_LEN 15
#define MIN_PATH_LEN_CONSTRAINT (-2)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HcfX509DistinguishedNameOpensslImpl HcfX509DistinguishedNameOpensslImpl;
struct HcfX509DistinguishedNameOpensslImpl {
    HcfX509DistinguishedNameSpi base;
    X509_NAME *name;
};

typedef enum {
    NAME_TYPE_SUBJECT,
    NAME_TYPE_ISSUER,
    NAME_TYPE_AUKEYID,
    NAME_TYPE_SUBKEYID
} X509NameType;

const char *GetAlgorithmName(const char *oid);
void CfPrintOpensslError(void);
CfResult DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob);
CfResult DeepCopyBlobToBlob(const CfBlob *inBlob, CfBlob **outBlob);
CfResult CopyExtensionsToBlob(const X509_EXTENSIONS *exts, CfBlob *outBlob);
CfResult CompareDateWithCertTime(const X509 *x509, const ASN1_TIME *inputDate);
CfResult ConvertNameDerDataToString(const unsigned char *data, uint32_t derLen, CfBlob *out);
CfResult CompareNameObject(const X509 *cert, const CfBlob *derBlob, X509NameType type, bool *compareRes);
CfResult CompareBigNum(const CfBlob *lhs, const CfBlob *rhs, int *out);
uint8_t *GetX509EncodedDataStream(const X509 *certificate, int *dataLength);
char *Asn1TimeToStr(const ASN1_GENERALIZEDTIME *time);
bool CfArrayContains(const CfArray *self, const CfArray *sub);
CfResult DeepCopyDataToOut(const char *data, uint32_t len, CfBlob *out);
CfResult DeepCopyDataToOutEx(const char *data, uint32_t len, CfBlob *out);
void SubAltNameArrayDataClearAndFree(SubAltNameArray *array);
bool CheckIsSelfSigned(const X509 *cert);
bool CheckIsLeafCert(X509 *cert);
CfResult IsOrderCertChain(STACK_OF(X509) * certsChain, bool *isOrder);
CfResult CheckSelfPubkey(X509 *cert, const EVP_PKEY *pubKey);
X509 *FindCertificateBySubject(STACK_OF(X509) * certs, X509_NAME *subjectName);
CfResult GetPubKeyDataFromX509(X509 *x509, CfBlob **pub);
CfResult GetSubjectNameFromX509(X509 *cert, CfBlob **sub);
CfResult GetNameConstraintsFromX509(X509 *cert, CfBlob **name);
CfResult CopyMemFromBIO(BIO *bio, CfBlob *outBlob);
CfResult CfDeepCopyExtendedKeyUsage(const STACK_OF(ASN1_OBJECT) *extUsage,
    int32_t index, CfArray *keyUsageOut);
CfResult CfDeepCopyAlternativeNames(const STACK_OF(GENERAL_NAME) *altNames, int32_t index, CfArray *outName);
CfResult CfDeepCopySubAltName(
    const STACK_OF(GENERAL_NAME) *altname, int32_t index, const SubAltNameArray *subAltNameArrayOut);
CfResult CfDeepCopyCertPolices(const CERTIFICATEPOLICIES *certPolicesIn, int32_t index, CfArray *certPolices);
CfResult CfConvertAsn1String2BoolArray(const ASN1_BIT_STRING *string, CfBlob *boolArr);
bool CfCompareGN2Blob(const GENERAL_NAME *gen, CfBlob *nc);
CfResult CfGetCRLDpURI(STACK_OF(DIST_POINT) *crlDp, CfArray *outURI);
X509_CRL *GetCrlFromCert(const HcfX509CertChainValidateParams *params, X509 *x509, int *errReason);
X509_CRL *GetCrlFromCertByDp(X509 *x509, int *errReason);
CfResult ValidateDate(const STACK_OF(X509) *x509CertChain, CfBlob *date);
CfResult ValidateCertDate(X509 *cert, CfBlob *date);
#ifdef __cplusplus
}
#endif

#endif
