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

#include "cf_adapter_extension_openssl.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "securec.h"

#include "cf_check.h"
#include "cf_log.h"
#include "cf_magic.h"
#include "cf_memory.h"
#include "cf_result.h"

#define KEYUSAGE_SHIFT 8
#define CRITICAL_SIZE  1

typedef struct {
    char *oid;
    char *extensionName;
} OidToExtensionName;

static const OidToExtensionName OID_TO_EXT_NAME_MAP[] = {
    { "2.5.29.9", "SubjectDirectoryAttributes" },
    { "2.5.29.14", "SubjectKeyIdentifier" },
    { "2.5.29.15", "KeyUsage" },
    { "2.5.29.16", "PrivateKeyUsage" },
    { "2.5.29.17", "SubjectAlternativeName" },
    { "2.5.29.18", "IssuerAlternativeName" },
    { "2.5.29.19", "BasicConstraints" },
    { "2.5.29.20", "CRLNumber" },
    { "2.5.29.21", "CRLReason" },
    { "2.5.29.23", "HoldInstructionCode" },
    { "2.5.29.24", "InvalidityDate" },
    { "2.5.29.27", "DeltaCRLIndicator" },
    { "2.5.29.28", "IssuingDistributionPoint" },
    { "2.5.29.29", "CertificateIssuer" },
    { "2.5.29.30", "NameConstraints" },
    { "2.5.29.31", "CRLDistributionPoints" },
    { "2.5.29.32", "CertificatePolicies" },
    { "2.5.29.33", "PolicyMappings" },
    { "2.5.29.35", "AuthorityKeyIdentifier" },
    { "2.5.29.36", "PolicyConstraints" },
    { "2.5.29.37", "ExtendedKeyUsage" },
    { "2.5.29.46", "FreshestCRL" },
    { "2.5.29.54", "InhibitAnyPolicy" },
    { "1.3.6.1.5.5.7.1.1", "AuthInfoAccess" },
    { "1.3.6.1.5.5.7.1.11", "SubjectInfoAccess" },
    { "1.3.6.1.5.5.7.48.1.5", "OCSPNoCheck" },
    { "2.16.840.1.113730.1.1", "NETSCAPECert" }
};

int32_t CfOpensslCreateExtension(const CfEncodingBlob *inData, CfBase **object)
{
    if ((CfCheckEncodingBlob(inData, MAX_LEN_EXTENSIONS) != CF_SUCCESS) ||
        (inData->encodingFormat != CF_FORMAT_DER) || (object == NULL)) {
        CF_LOG_E("invalid input params");
        return CF_INVALID_PARAMS;
    }

    CfOpensslExtensionObj *extsObj = CfMalloc(sizeof(CfOpensslExtensionObj), 0);
    if (extsObj == NULL) {
        CF_LOG_E("malloc failed");
        return CF_ERR_MALLOC;
    }
    extsObj->base.type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION);

    uint8_t *end = inData->data; /* data pointer will shift downward in d2i_X509_EXTENSIONS */
    extsObj->exts = d2i_X509_EXTENSIONS(NULL, (const unsigned char **)&end, inData->len);
    if (extsObj->exts == NULL) {
        CF_LOG_E("Failed to get internal extension");
        CfFree(extsObj);
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (end != (inData->data + inData->len)) { /* Tainted extension data: valid part + invalid part */
        CF_LOG_E("The extension indata is invalid");
        sk_X509_EXTENSION_pop_free(extsObj->exts, X509_EXTENSION_free);
        CfFree(extsObj);
        return CF_ERR_CRYPTO_OPERATION;
    }

    *object = &extsObj->base;
    return CF_SUCCESS;
}

void CfOpensslDestoryExtension(CfBase **object)
{
    if ((object == NULL) || (*object == NULL)) {
        CF_LOG_E("invalid input params");
        return;
    }

    CfOpensslExtensionObj *extsObj = (CfOpensslExtensionObj *)*object;
    if (extsObj->base.type != CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION)) {
        CF_LOG_E("the object is invalid , type = %lu", extsObj->base.type);
        return;
    }

    if (extsObj->exts != NULL) {
        sk_X509_EXTENSION_pop_free(extsObj->exts, X509_EXTENSION_free);
    }
    CfFree(extsObj);
    *object = NULL;
    return;
}

static int32_t CheckObjectAndGetExts(const CfBase *object, X509_EXTENSIONS **exts)
{
    CfOpensslExtensionObj *extsObj = (CfOpensslExtensionObj *)object;
    if (extsObj->base.type != CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_EXTENSION)) {
        CF_LOG_E("the object is invalid , type = %lu", extsObj->base.type);
        return CF_INVALID_PARAMS;
    }

    if (extsObj->exts == NULL) {
        CF_LOG_E("extension is null");
        return CF_INVALID_PARAMS;
    }

    *exts = extsObj->exts;
    return CF_SUCCESS;
}

static int32_t CopyIndexArray(uint32_t *destArray, uint32_t *destLen, const uint32_t *srcArray, uint32_t srcLen)
{
    if (memcpy_s(destArray, ((*destLen) * sizeof(uint32_t)), srcArray, (srcLen * sizeof(uint32_t))) != EOK) {
        CF_LOG_E("Failed to copy index array");
        return CF_ERR_COPY;
    }
    *destLen = srcLen;
    return CF_SUCCESS;
}

static int32_t GetExtensionIndexArray(const X509_EXTENSIONS *exts, CfExtensionOidType type,
    uint32_t *array, uint32_t *arrayLen)
{
    int32_t extNums = sk_X509_EXTENSION_num(exts);
    if ((extNums <= 0) || (extNums > MAX_COUNT_OID)) {
        CF_LOG_E("Failed to get extension numbers");
        return CF_ERR_CRYPTO_OPERATION;
    }

    uint32_t allOidArray[MAX_COUNT_OID] = { 0 }; /* type: CF_EXT_TYPE_ALL_OIDS */
    uint32_t critOidArray[MAX_COUNT_OID] = { 0 }; /* type: CF_EXT_TYPE_CRITICAL_OIDS */
    uint32_t uncritOidArray[MAX_COUNT_OID] = { 0 }; /* type: CF_EXT_TYPE_UNCRITICAL_OIDS */
    uint32_t critCnt = 0;
    uint32_t uncritCnt = 0;

    for (uint32_t i = 0; i < (uint32_t)extNums; ++i) {
        allOidArray[i] = i;

        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        if (ex == NULL) {
            CF_LOG_E("Failed to get exts [%u] value", i);
            return CF_ERR_CRYPTO_OPERATION;
        }

        int crit = X509_EXTENSION_get_critical(ex);
        if (crit == 1) {
            critOidArray[critCnt++] = i;
        } else {
            uncritOidArray[uncritCnt++] = i;
        }
    }

    switch (type) {
        case CF_EXT_TYPE_ALL_OIDS:
            return CopyIndexArray(array, arrayLen, allOidArray, (uint32_t)extNums);
        case CF_EXT_TYPE_CRITICAL_OIDS:
            return CopyIndexArray(array, arrayLen, critOidArray, critCnt);
        case CF_EXT_TYPE_UNCRITICAL_OIDS:
            return CopyIndexArray(array, arrayLen, uncritOidArray, uncritCnt);
        default:
            CF_LOG_E("type is invalid");
            return CF_INVALID_PARAMS;
    }
}

static int32_t DeepCopyDataToOutblob(const char *data, uint32_t len, CfBlob *outBlob)
{
    outBlob->data = (uint8_t *)CfMalloc(len, 0);
    if (outBlob->data == NULL) {
        CF_LOG_E("Failed to malloc");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(outBlob->data, len, data, len);
    outBlob->size = len;
    return CF_SUCCESS;
}

static int32_t DeepCopyOidsToOut(const X509_EXTENSIONS *exts, const uint32_t *idxArray, uint32_t arrayLen,
    CfBlobArray *out)
{
    uint32_t memSize = sizeof(CfBlob) * arrayLen;
    CfBlob *dataArray = (CfBlob *)CfMalloc(memSize, 0);
    if (dataArray == NULL) {
        CF_LOG_E("Failed to malloc");
        return CF_ERR_MALLOC;
    }

    for (uint32_t i = 0; i < arrayLen; ++i) {
        uint32_t index = idxArray[i];

        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, index);
        if (ex == NULL) {
            CF_LOG_E("Failed to get exts [%u] value", index);
            FreeCfBlobArray(dataArray, i);
            return CF_ERR_CRYPTO_OPERATION;
        }

        char oid[MAX_LEN_OID] = { 0 };
        int32_t oidLen = OBJ_obj2txt(oid, MAX_LEN_OID, X509_EXTENSION_get_object(ex), 1);
        if ((oidLen <= 0) || (oidLen >= MAX_LEN_OID)) {
            CF_LOG_E("Failed to get oid[%u]", index);
            FreeCfBlobArray(dataArray, i);
            return CF_ERR_CRYPTO_OPERATION;
        }

        int32_t ret = DeepCopyDataToOutblob(oid, strlen(oid), &dataArray[i]);
        if (ret != CF_SUCCESS) {
            CF_LOG_E("Failed to copy oid[%u]", index);
            FreeCfBlobArray(dataArray, i);
            return ret;
        }
    }

    out->data = dataArray;
    out->count = arrayLen;
    return CF_SUCCESS;
}

int32_t CfOpensslGetOids(const CfBase *object, CfExtensionOidType type, CfBlobArray *out)
{
    if ((object == NULL) || (out == NULL)) {
        CF_LOG_E("invalid input params");
        return CF_INVALID_PARAMS;
    }

    X509_EXTENSIONS *exts = NULL;
    int32_t ret = CheckObjectAndGetExts(object, &exts);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to get extension");
        return ret;
    }

    uint32_t idxArray[MAX_COUNT_OID] = { 0 }; /* extension index array for target CfExtensionOidType */
    uint32_t count = MAX_COUNT_OID;
    ret = GetExtensionIndexArray(exts, type, idxArray, &count);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to get extension index array");
        return ret;
    }

    ret = DeepCopyOidsToOut(exts, idxArray, count, out);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to copy oids to out");
        return ret;
    }
    return CF_SUCCESS;
}

int32_t CfOpensslHasUnsupportedCriticalExtension(const CfBase *object, bool *out)
{
    if (object == NULL || out == NULL) {
        CF_LOG_E("invalid input params");
        return CF_INVALID_PARAMS;
    }

    X509_EXTENSIONS *exts = NULL;
    int32_t ret = CheckObjectAndGetExts(object, &exts);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to get extension");
        return ret;
    }

    int32_t extNums = sk_X509_EXTENSION_num(exts);
    if ((extNums <= 0) || (extNums > MAX_COUNT_OID)) {
        CF_LOG_E("Failed to get extension numbers, extNums = %d", extNums);
        return CF_ERR_CRYPTO_OPERATION;
    }

    for (uint32_t i = 0; i < (uint32_t)extNums; ++i) {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        if (ex == NULL) {
            CF_LOG_E("Failed to get exts [%u] value", i);
            return CF_ERR_CRYPTO_OPERATION;
        }

        int crit = X509_EXTENSION_get_critical(ex);
        if (crit != 1) { /* the extension entry is critical */
            continue;
        }

        char oid[MAX_LEN_OID] = { 0 };
        int32_t oidLen = OBJ_obj2txt(oid, MAX_LEN_OID, X509_EXTENSION_get_object(ex), 1);
        if ((oidLen <= 0) || (oidLen >= MAX_LEN_OID)) {
            CF_LOG_E("Failed to get ext oid");
            return CF_ERR_CRYPTO_OPERATION;
        }
        uint32_t oidsCount = sizeof(OID_TO_EXT_NAME_MAP) / sizeof(OidToExtensionName);
        bool match = false;
        for (uint32_t oidInd = 0; oidInd < oidsCount; oidInd++) {
            if (strcmp(OID_TO_EXT_NAME_MAP[oidInd].oid, oid) == 0) {
                match = true;
                break;
            }
        }
        if (!match) {
            CF_LOG_I("extension oid [%s] is not supported.", oid);
            *out = true;
            return CF_SUCCESS;
        }
    }
    *out = false;
    return CF_SUCCESS;
}

static int GetTargetNid(const CfBlob *oid)
{
    uint32_t length = oid->size + 1; /* add '\0' in the end */
    uint8_t *oidString = (uint8_t *)CfMalloc(length, 0);
    if (oidString == NULL) {
        CF_LOG_E("Failed to malloc oid string");
        return CF_ERR_MALLOC;
    }

    if (memcpy_s(oidString, length, oid->data, oid->size) != EOK) {
        CF_LOG_E("Failed to copy oid string");
        CfFree(oidString);
        return CF_ERR_COPY;
    }

    int nid = OBJ_txt2nid((char *)oidString);
    CfFree(oidString);
    return nid;
}

static int32_t FoundExtMatchedNid(const X509_EXTENSIONS *exts, int targetNid, X509_EXTENSION **found)
{
    int32_t extNums = sk_X509_EXTENSION_num(exts);
    if ((extNums <= 0) || (extNums > MAX_COUNT_OID)) {
        CF_LOG_E("Failed to get extension numbers");
        return CF_ERR_CRYPTO_OPERATION;
    }

    for (int i = 0; i < extNums; ++i) {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        if (ex == NULL) {
            CF_LOG_E("Failed to get exts [%d] value", i);
            return CF_ERR_CRYPTO_OPERATION;
        }

        int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ex));
        if ((nid == NID_undef) || (nid > MAX_COUNT_NID)) {
            CF_LOG_E("nid undefined");
            return CF_ERR_CRYPTO_OPERATION;
        }

        if (targetNid == nid) {
            *found = ex;
            return CF_SUCCESS;
        }
    }
    return CF_NOT_EXIST;
}

static int32_t GetEntry(const X509_EXTENSION *found, CfBlob *out)
{
    unsigned char *entry = NULL;
    int entryLen = i2d_X509_EXTENSION((X509_EXTENSION *)found, &entry);
    if (entryLen <= 0) {
        CF_LOG_E("Failed to get entry");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = DeepCopyDataToOutblob((const char *)entry, entryLen, out);
    OPENSSL_free(entry);
    return ret;
}

static int32_t GetEntryCritical(const X509_EXTENSION *found, CfBlob *out)
{
    out->data = (uint8_t *)CfMalloc(1, 0); /* critical value is 0 or 1 */
    if (out->data == NULL) {
        CF_LOG_E("Failed to malloc");
        return CF_ERR_MALLOC;
    }
    out->size = CRITICAL_SIZE;

    int crit = X509_EXTENSION_get_critical(found);
    if (crit == 1) {
        out->data[0] = 1;
    } else {
        out->data[0] = 0;
    }

    return CF_SUCCESS;
}

static int32_t GetEntryValue(const X509_EXTENSION *found, CfBlob *out)
{
    /* return internal value: extension data */
    ASN1_OCTET_STRING *octetString = X509_EXTENSION_get_data((X509_EXTENSION *)found);
    if (octetString == NULL) {
        CF_LOG_E("Failed to get entry value");
        return CF_ERR_CRYPTO_OPERATION;
    }

    unsigned char *entryValue = NULL;
    int entryValueLen = i2d_ASN1_OCTET_STRING(octetString, &entryValue);
    if (entryValueLen <= 0) {
        CF_LOG_E("Failed to get entry value len");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = DeepCopyDataToOutblob((char *)entryValue, entryValueLen, out);
    OPENSSL_free(entryValue);
    return ret;
}

static int32_t GetMatchedEntry(const X509_EXTENSION *found, CfExtensionEntryType type, CfBlob *out)
{
    switch (type) {
        case CF_EXT_ENTRY_TYPE_ENTRY:
            return GetEntry(found, out);
        case CF_EXT_ENTRY_TYPE_ENTRY_CRITICAL:
            return GetEntryCritical(found, out);
        case CF_EXT_ENTRY_TYPE_ENTRY_VALUE:
            return GetEntryValue(found, out);
        default:
            CF_LOG_E("type id invalid");
            return CF_INVALID_PARAMS;
    }
}

int32_t CfOpensslGetEntry(const CfBase *object, CfExtensionEntryType type, const CfBlob *oid, CfBlob *out)
{
    if ((object == NULL) || (out == NULL) || (CfCheckBlob(oid, MAX_LEN_OID) != CF_SUCCESS)) {
        CF_LOG_E("invalid input params");
        return CF_INVALID_PARAMS;
    }

    X509_EXTENSIONS *exts = NULL;
    int32_t ret = CheckObjectAndGetExts(object, &exts);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to get extension");
        return ret;
    }

    /* get target nid from oid */
    int targetNid = GetTargetNid(oid);
    if ((targetNid == NID_undef) || (targetNid > MAX_COUNT_NID)) {
        CF_LOG_E("nid is undefined");
        return CF_INVALID_PARAMS;
    }

    /* found one extension matched target nid in extensions */
    X509_EXTENSION *found = NULL;
    ret = FoundExtMatchedNid(exts, targetNid, &found);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("no found target nid");
        return ret;
    }

    /* get entry from matched extension for target type */
    ret = GetMatchedEntry(found, type, out);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to get matched entry");
        return ret;
    }
    return CF_SUCCESS;
}

static int32_t CheckKeyUsage(const X509_EXTENSIONS *exts, int32_t *pathLen)
{
    ASN1_BIT_STRING *usage = (ASN1_BIT_STRING *)X509V3_get_d2i(exts, NID_key_usage, NULL, NULL);
    if (usage == NULL) {
        CF_LOG_E("Failed to get usage");
        return CF_ERR_CRYPTO_OPERATION;
    }

    uint32_t keyUsage = (uint32_t)usage->data[0];
    if (usage->length > 1) {
        keyUsage |= ((uint32_t)usage->data[1] << KEYUSAGE_SHIFT);
    }

    /* keyUsage of a CA cert: sign */
    if ((keyUsage & KU_KEY_CERT_SIGN) == 0) {
        CF_LOG_I("this cert not a CA");
        *pathLen = BASIC_CONSTRAINTS_NO_CA;
    }

    ASN1_BIT_STRING_free(usage);
    return CF_SUCCESS;
}

static int32_t CheckBasicConstraints(const X509_EXTENSIONS *exts, int32_t *pathLen)
{
    BASIC_CONSTRAINTS *bs = (BASIC_CONSTRAINTS *)X509V3_get_d2i(exts, NID_basic_constraints, NULL, NULL);
    if (bs == NULL) {
        CF_LOG_E("Failed to get basic constraints");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = CF_SUCCESS;
    do {
        if (!bs->ca) {
            CF_LOG_I("this cert not a CA");
            /* CheckCA operation is success, but cert is not a CA, pathLen set -1 */
            *pathLen = BASIC_CONSTRAINTS_NO_CA;
            ret = CF_SUCCESS;
            break;
        }

        if ((bs->pathlen == NULL) || (bs->pathlen->type == V_ASN1_NEG_INTEGER)) {
            CF_LOG_I("this cert pathlen no limit");
            /* CheckCA operation is success and cert is a CA, but no limit to pathlen, pathLen set -2 */
            *pathLen = BASIC_CONSTRAINTS_PATHLEN_NO_LIMIT;
            ret = CF_SUCCESS;
            break;
        }

        long len = ASN1_INTEGER_get(bs->pathlen);
        if ((len < 0) || (len > INT_MAX)) { /* CheckCA operation is exceptional, pathlen is invalid */
            CF_LOG_E("this cert pathlen is invalid");
            ret = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        *pathLen = (int32_t)len;
    } while (0);

    BASIC_CONSTRAINTS_free(bs);
    return ret;
}

int32_t CfOpensslCheckCA(const CfBase *object, int32_t *pathLen)
{
    if ((object == NULL) || (pathLen == NULL)) {
        CF_LOG_E("invalid input params");
        return CF_INVALID_PARAMS;
    }

    X509_EXTENSIONS *exts = NULL;
    int32_t ret = CheckObjectAndGetExts(object, &exts);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to get extension");
        return ret;
    }

    *pathLen = 0;
    ret = CheckKeyUsage(exts, pathLen);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to check keyUsage");
        return ret;
    }
    if (*pathLen != 0) { /* checkKeyUsage operation success, but cert has no signing purpose, pathLen set -1. */
        CF_LOG_I("Return: this cert not a CA");
        return ret;
    }

    ret = CheckBasicConstraints(exts, pathLen);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to check basicConstraints");
        return ret;
    }
    return ret;
}

static int32_t GetExtensionEncoded(const X509_EXTENSIONS *inExts, CfBlob *out)
{
    unsigned char *derExts = NULL;
    int extsLen = i2d_X509_EXTENSIONS((X509_EXTENSIONS *)inExts, &derExts);
    if (extsLen <= 0) {
        CF_LOG_E("Failed to convert internal exts to der format");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = DeepCopyDataToOutblob((const char *)derExts, extsLen, out);
    OPENSSL_free(derExts);
    return ret;
}

int32_t CfOpensslGetExtensionItem(const CfBase *object, CfItemId id, CfBlob *out)
{
    if ((out == NULL) || (object == NULL)) {
        CF_LOG_E("invalid input params");
        return CF_INVALID_PARAMS;
    }

    X509_EXTENSIONS *inExts = NULL;
    int32_t ret = CheckObjectAndGetExts(object, &inExts);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to get extension");
        return ret;
    }

    switch (id) {
        case CF_ITEM_ENCODED:
            return GetExtensionEncoded(inExts, out);
        default:
            CF_LOG_E("id is invalid");
            return CF_INVALID_PARAMS;
    }
    return CF_SUCCESS;
}
