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

#include "x509_distinguished_name_openssl.h"

#include <securec.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "config.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "cf_blob.h"
#include "result.h"
#include "utils.h"
#include "x509_distinguished_name_spi.h"
#include "certificate_openssl_common.h"

#define X509_DISTINGUISHED_NAME_OPENSSL_CLASS "X509DistinguishedNameOpensslClass"

typedef struct {
    HcfX509DistinguishedNameSpi base;
    X509_NAME *name;
} HcfX509DistinguishedNameOpensslImpl;

static const char *GetX509DistinguishedNameClass(void)
{
    return X509_DISTINGUISHED_NAME_OPENSSL_CLASS;
}

static void DestroyX509DistinguishedNameOpenssl(CfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetX509DistinguishedNameClass())) {
        LOGE("Input wrong class type!");
        return;
    }
    HcfX509DistinguishedNameOpensslImpl *realName = (HcfX509DistinguishedNameOpensslImpl *)self;
    X509_NAME_free(realName->name);
    realName->name = NULL;
    CfFree(realName);
}

static CfResult GetEncodeOpenssl(HcfX509DistinguishedNameSpi *self, CfEncodingBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509DistinguishedNameClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfX509DistinguishedNameOpensslImpl *realName = (HcfX509DistinguishedNameOpensslImpl *)self;
    size_t len = 0;
    const unsigned char *p = NULL;
    if (X509_NAME_get0_der(realName->name, &p, &len) == 1) {
        out->data = (uint8_t *)CfMalloc((uint32_t)len, 0);
        if (out->data == NULL) {
            LOGE("Failed to malloc for encoded data!");
            return CF_ERR_MALLOC;
        }
        if (memcpy_s(out->data, len, p, len) != EOK) {
            LOGE("memcpy_s data to buffer failed!");
            CfFree(out->data);
            return CF_ERR_COPY;
        }

        out->len = len;
        out->encodingFormat = CF_FORMAT_DER;
        return CF_SUCCESS;
    }

    LOGE("X509_NAME_get0_der error!");
    return CF_ERR_CRYPTO_OPERATION;
}

static CfResult GetDataByEntryOpenssl(int32_t count, CfArray *outArr, X509_NAME_ENTRY **neArr)
{
    if (count <= 0 || outArr == NULL || *neArr == NULL) {
        LOGE("GetDataByEntryOpenssl data is null!");
        return CF_INVALID_PARAMS;
    }

    outArr->data = (CfBlob *)CfMalloc(count*sizeof(CfBlob), 0);
    if (outArr->data == NULL) {
        LOGE("CfMalloc error");
        return CF_ERR_MALLOC;
    }
    outArr->count = count;
    for (int i = 0; i < count; ++i) {
        ASN1_STRING *str = X509_NAME_ENTRY_get_data(neArr[i]);
        unsigned char *p = ASN1_STRING_data(str);
        int len = ASN1_STRING_length(str);
        if (len <= 0) {
            LOGE("ASN1_STRING_length error");
            CfArrayDataClearAndFree(outArr);
            return CF_ERR_CRYPTO_OPERATION;
        }
        CfResult res = DeepCopyDataToOut((const char *)p, len, &(outArr->data[i]));
        if (res != CF_SUCCESS) {
            LOGE("DeepCopyDataToOut error");
            CfArrayDataClearAndFree(outArr);
            return res;
        }
    }
    return CF_SUCCESS;
}

static CfResult GetNameTypeByOpenssl(HcfX509DistinguishedNameOpensslImpl *realName, CfBlob *type, CfArray *outArr)
{
    if (realName == NULL || type == NULL || outArr == NULL) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }

    if (type->size < 1) {
        LOGE("The input type size is zero!");
        return CF_INVALID_PARAMS;
    }
    X509_NAME_ENTRY **neArr = (X509_NAME_ENTRY **)CfMalloc(
        X509_NAME_entry_count(realName->name) * sizeof(X509_NAME_ENTRY *), 0);
    if (neArr == NULL) {
        LOGE("CfMalloc error");
        return CF_ERR_MALLOC;
    }

    int j = 0;
    for (int i = 0; i < X509_NAME_entry_count(realName->name); ++i) {
        X509_NAME_ENTRY *ne = X509_NAME_get_entry(realName->name, i);
        ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ne);
        int nid = OBJ_obj2nid(obj);
        const char *str = OBJ_nid2sn(nid);
        if (str == NULL) {
            LOGE("OBJ_nid2sn error!");
            CfFree(neArr);
            return CF_ERR_CRYPTO_OPERATION;
        }

        if (strlen(str) == (unsigned int)(type->size - 1) && memcmp(str, type->data, strlen(str)) == 0) {
            neArr[j++] = ne;
        }
    }

    if (j > 0) {
        CfResult res = GetDataByEntryOpenssl(j, outArr, neArr);
        CfFree(neArr);
        return res;
    }

    CfFree(neArr);
    return CF_SUCCESS;
}

static CfResult GetNameOpenssl(HcfX509DistinguishedNameSpi *self, CfBlob *type, CfBlob *out, CfArray *outArr)
{
    if (self == NULL) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509DistinguishedNameClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfX509DistinguishedNameOpensslImpl *realName = (HcfX509DistinguishedNameOpensslImpl *)self;
    if (out != NULL) {
        char *oneline = X509_NAME_oneline(realName->name, NULL, 0);
        if (oneline == NULL) {
            LOGE("X509_NAME_oneline error");
            return CF_ERR_CRYPTO_OPERATION;
        }
        CfResult res = DeepCopyDataToOut(oneline, strlen(oneline), out);
        OPENSSL_free(oneline);
        return res;
    }
    return GetNameTypeByOpenssl(realName, type, outArr);
}

static CfResult SetValueToX509Name(X509_NAME *name, int chtype, char *typestr, unsigned char *valstr, int isMulti)
{
    int nid = OBJ_txt2nid(typestr);
    if (nid == NID_undef) {
        LOGW("Ignore unknown name attribute");
        return CF_SUCCESS;
    }

    if (*valstr == '\0') {
        LOGW("No value provided for name attribute");
        return CF_SUCCESS;
    }

    if (!X509_NAME_add_entry_by_NID(name, nid, chtype, valstr, strlen((char *)valstr), -1, isMulti ? -1 : 0)) {
        LOGE("Error adding name attribute");
        return CF_INVALID_PARAMS;
    }
    return CF_SUCCESS;
}

static CfResult CollectAndParseName(const char *cp, char *work, int chtype, X509_NAME *name)
{
    int multiFlag = 0;
    while (*cp != '\0') {
        char *bp = work;
        char *typestr = bp;
        int isMulti = multiFlag;
        multiFlag = 0;

        while (*cp != '\0' && *cp != '=') {
            *bp++ = *cp++;
        }
        *bp++ = '\0';
        if (*cp == '\0') {
            LOGE("Not has RDN type string");
            return CF_INVALID_PARAMS;
        }
        cp++;

        unsigned char *valstr = (unsigned char *)bp;
        while (*cp != '\0' && *cp != '/') {
            if (*cp == '+') {
                multiFlag = 1;
                break;
            }
            const char *t = cp;
            t++;
            if (*cp == '\\' && *t == '\0') {
                LOGE("Escape character at end of name string");
                return CF_INVALID_PARAMS;
            }
            if (*cp == '\\') {
                cp++;
            }
            *bp++ = *cp++;
        }
        *bp++ = '\0';
        if (*cp != '\0') {
            cp++;
        }

        int ret = SetValueToX509Name(name, chtype, typestr, valstr, isMulti);
        if (ret != CF_SUCCESS) {
            return ret;
        }
    }
    return CF_SUCCESS;
}

static X509_NAME *ParseName(const char *cp, int chtype, const char *desc)
{
    if (*cp++ != '/') {
        LOGE("name is expected to be in the format");
        return NULL;
    }

    X509_NAME *name = X509_NAME_new();
    if (name == NULL) {
        LOGE("Out of memory");
        return NULL;
    }
    char *work = OPENSSL_strdup(cp);
    if (work == NULL) {
        LOGE("Error copying name input");
        goto err;
    }

    if (CollectAndParseName(cp, work, chtype, name) != CF_SUCCESS) {
        LOGE("Error CollectAndParseName");
        goto err;
    }

    OPENSSL_free(work);
    return name;

 err:
    X509_NAME_free(name);
    OPENSSL_free(work);
    return NULL;
}

CfResult OpensslX509DistinguishedNameSpiCreate(const CfBlob *inStream, const bool bString,
                                               HcfX509DistinguishedNameSpi **spi)
{
    if ((inStream == NULL) || (spi == NULL)) {
        LOGE("The input data blob is null!");
        return CF_INVALID_PARAMS;
    }
    X509_NAME *name = NULL;
    if (bString) {
        name = ParseName((const char *)inStream->data, MBSTRING_UTF8, "DistinguishedName");
    } else {
        name = d2i_X509_NAME(NULL, (const unsigned char **)&inStream->data, inStream->size);
    }

    if (name == NULL) {
        LOGE("the name is null!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    HcfX509DistinguishedNameOpensslImpl *realName = (HcfX509DistinguishedNameOpensslImpl *)CfMalloc(
        sizeof(HcfX509DistinguishedNameOpensslImpl), 0);
    if (realName == NULL) {
        LOGE("CfMalloc error");
        return CF_ERR_MALLOC;
    }

    realName->name = name;
    realName->base.base.getClass = GetX509DistinguishedNameClass;
    realName->base.base.destroy = DestroyX509DistinguishedNameOpenssl;
    realName->base.engineGetEncode = GetEncodeOpenssl;
    realName->base.engineGetName = GetNameOpenssl;
    *spi = (HcfX509DistinguishedNameSpi *)realName;
    return CF_SUCCESS;
}
