/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "revocation_check.h"

#include <string.h>

#include "cf_blob.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "securec.h"

#include "openssl/sha.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include "revocation_cache.h"

static bool GetCertDer(HcfX509Certificate *cert, CfEncodingBlob *encoded)
{
    encoded->data = NULL;
    encoded->len = 0;
    encoded->encodingFormat = CF_FORMAT_DER;
    CfResult ret = cert->base.getEncoded((HcfCertificate *)cert, encoded);
    if (ret != CF_SUCCESS || encoded->data == NULL || encoded->len == 0) {
        LOGW("revocation: get cert encoded failed, ret=%d", ret);
        if (encoded->data != NULL) {
            CF_FREE_PTR(encoded->data);
        }
        return false;
    }
    return true;
}

static X509 *ParseX509FromDer(const CfEncodingBlob *encoded)
{
    const uint8_t *p = encoded->data;
    X509 *x509 = d2i_X509(NULL, &p, (long)encoded->len);
    if (x509 == NULL) {
        LOGW("revocation: d2i_X509 failed");
    }
    return x509;
}

static bool ComputeSpkiSha256(X509 *x509, uint8_t *digestOut)
{
    EVP_PKEY *pkey = X509_get0_pubkey(x509);
    if (pkey == NULL) {
        LOGW("revocation: X509_get0_pubkey failed");
        return false;
    }
    unsigned char *spkiDer = NULL;
    int spkiLen = i2d_PUBKEY(pkey, &spkiDer);
    if (spkiLen <= 0) {
        OPENSSL_free(spkiDer);
        LOGW("revocation: i2d_PUBKEY failed");
        return false;
    }
    SHA256(spkiDer, (size_t)spkiLen, digestOut);
    OPENSSL_free(spkiDer);
    return true;
}

static bool ExtractAkiKeyId(X509 *x509, uint8_t *akiOut)
{
    AUTHORITY_KEYID *akid = X509_get_ext_d2i(x509, NID_authority_key_identifier, NULL, NULL);
    if (akid == NULL || akid->keyid == NULL) {
        LOGD("revocation: cert has no AKI keyIdentifier, skip type2");
        if (akid != NULL) {
            AUTHORITY_KEYID_free(akid);
        }
        return false;
    }
    ASN1_OCTET_STRING *keyid = akid->keyid;
    bool ok = false;
    if (keyid->length == REVOCATION_AKI_LEN && keyid->data != NULL) {
        if (memcpy_s(akiOut, REVOCATION_AKI_LEN, keyid->data, REVOCATION_AKI_LEN) == EOK) {
            ok = true;
        } else {
            LOGE("revocation: memcpy_s aki failed");
        }
    } else {
        LOGW("revocation: AKI keyId length=%d (expect %d), skip", keyid->length, REVOCATION_AKI_LEN);
    }
    AUTHORITY_KEYID_free(akid);
    return ok;
}

/* Number of digits in the UTCTime date part (YYMMDD). */
#define REVOCATION_UTCTIME_DATE_DIGITS 6

static bool IsAllDigits(const char *str, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
    }
    return true;
}

/* Parse UTCTime (YYMMDD...) into YYYYMMDD string (9 bytes with NUL) */
static bool ParseUtcTime(const char *date, char *yyyyMmDd)
{
    uint32_t yy = (uint32_t)((date[0] - '0') * REVOCATION_DECIMAL_BASE + (date[1] - '0'));
    uint32_t year = (yy >= REVOCATION_UTCTIME_YEAR_THRESHOLD) ?
        (REVOCATION_YEAR_BASE_1900 + yy) : (REVOCATION_YEAR_BASE_2000 + yy);
    if (snprintf_s(yyyyMmDd, REVOCATION_DATE_STR_LEN + 1, REVOCATION_DATE_STR_LEN,
        "%04u%c%c%c%c", year, date[2], date[3], date[4], date[5]) < 0) {
        LOGW("revocation: snprintf_s UTCTime failed");
        return false;
    }
    return true;
}

/* Parse GeneralizedTime (YYYYMMDD...) into YYYYMMDD string (9 bytes with NUL) */
static bool ParseGeneralizedTime(const char *date, char *yyyyMmDd)
{
    if (memcpy_s(yyyyMmDd, REVOCATION_DATE_STR_LEN + 1, date, REVOCATION_DATE_STR_LEN) != EOK) {
        LOGW("revocation: memcpy_s GeneralizedTime failed");
        return false;
    }
    yyyyMmDd[REVOCATION_DATE_STR_LEN] = '\0';
    return true;
}

/* Extract notBefore as YYYYMMDD string (9 bytes with NUL) for string comparison */
static bool GetNotBeforeDateStr(X509 *x509, char *yyyyMmDd)
{
    ASN1_TIME *notBefore = X509_get_notBefore(x509);
    if (notBefore == NULL) {
        LOGW("revocation: notBefore is null, skip type2");
        return false;
    }
    const char *date = (const char *)ASN1_STRING_get0_data(notBefore);
    int dateLen = ASN1_STRING_length(notBefore);
    if (date == NULL || dateLen == 0) {
        LOGW("revocation: notBefore data is empty, skip type2");
        return false;
    }
    if (dateLen == REVOCATION_UTCTIME_LEN) {
        if (!IsAllDigits(date, REVOCATION_UTCTIME_DATE_DIGITS)) {
            LOGW("revocation: UTCTime contains non-digit chars, skip type2");
            return false;
        }
        return ParseUtcTime(date, yyyyMmDd);
    }
    if (dateLen == REVOCATION_GENERALIZEDTIME_LEN) {
        if (!IsAllDigits(date, REVOCATION_DATE_STR_LEN)) {
            LOGW("revocation: GeneralizedTime contains non-digit chars, skip type2");
            return false;
        }
        return ParseGeneralizedTime(date, yyyyMmDd);
    }
    LOGE("revocation: notBefore dateLen=%d unsupported (11-byte UTCTime without seconds not supported), skip",
        dateLen);
    return false;
}

static bool CheckCertBySpki(X509 *x509, const RevocationCache *cloud, const RevocationCache *user)
{
    uint8_t sha256[REVOCATION_HASH_LEN];
    if (!ComputeSpkiSha256(x509, sha256)) {
        LOGW("revocation: compute spki sha256 failed, skip cert type1");
        return false;
    }
    if (RevocationCacheMatchSpki(user, sha256)) {
        return true;
    }
    return RevocationCacheMatchSpki(cloud, sha256);
}

static bool CheckCertByAki(X509 *x509, const RevocationCache *cloud, const RevocationCache *user)
{
    uint8_t aki[REVOCATION_AKI_LEN];
    if (!ExtractAkiKeyId(x509, aki)) {
        return false;
    }
    char notBefore[REVOCATION_DATE_STR_LEN + 1];
    if (!GetNotBeforeDateStr(x509, notBefore)) {
        return false;
    }
    if (RevocationCacheMatchAki(user, aki, notBefore)) {
        return true;
    }
    return RevocationCacheMatchAki(cloud, aki, notBefore);
}

static void FreeX509Array(X509 **x509s, uint32_t count)
{
    for (uint32_t i = 0; i < count; i++) {
        if (x509s[i] != NULL) {
            X509_free(x509s[i]);
        }
    }
    CF_FREE_PTR(x509s);
}

CfResult RevocationHcfCertToX509(HcfX509Certificate *cert, X509 **x509Out)
{
    if (cert == NULL || x509Out == NULL) {
        return CF_INVALID_PARAMS;
    }
    *x509Out = NULL;
    CfEncodingBlob encoded = { 0 };
    if (!GetCertDer(cert, &encoded)) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    X509 *x509 = ParseX509FromDer(&encoded);
    CF_FREE_PTR(encoded.data);
    if (x509 == NULL) {
        LOGW("revocation: parse x509 from der failed, skip cert");
        return CF_ERR_CRYPTO_OPERATION;
    }
    *x509Out = x509;
    return CF_SUCCESS;
}

/* Build the X509 array (no lock needed): slots that fail to parse stay NULL and
 * are skipped during scanning. Returns false on out-of-memory or count overflow. */
static bool BuildX509Array(const HcfX509CertificateArray *certs, X509 ***x509sOut, uint32_t *countOut)
{
    *x509sOut = NULL;
    *countOut = 0;
    if (certs->count > (uint32_t)(MAX_MEMORY_SIZE / sizeof(X509 *))) {
        LOGE("revocation: cert count=%u exceeds limit", certs->count);
        return false;
    }
    X509 **x509s = (X509 **)CfMalloc(certs->count * sizeof(X509 *), 0);
    if (x509s == NULL) {
        LOGE("revocation: malloc x509s array failed");
        return false;
    }
    for (uint32_t i = 0; i < certs->count; i++) {
        if (certs->data[i] == NULL) {
            LOGW("revocation: cert[%u] is null, skip", i);
            continue;
        }
        (void)RevocationHcfCertToX509(certs->data[i], &x509s[i]);
    }
    *x509sOut = x509s;
    *countOut = certs->count;
    return true;
}

/* Non-owning view over a caller-owned certificate container. */
typedef struct RevocationCertView {
    const void *ctx;
    uint32_t count;
    RevocationCertGetter getter;
} RevocationCertView;

static X509 *ArrayCertGetter(const void *ctx, uint32_t index)
{
    return ((X509 **)ctx)[index];
}

static X509 *StackCertGetter(const void *ctx, uint32_t index)
{
    return sk_X509_value((STACK_OF(X509) *)ctx, (int)index);
}

/* Scan the certificate view with a single cache snapshot; returns the first
 * matched cert index or -1. The cache must stay valid for the whole call (the
 * caller holds the read lock of the corresponding source). */
static int32_t FindFirstHitByCache(const RevocationCertView *view, const RevocationCache *cache)
{
    if (view == NULL || view->getter == NULL || cache == NULL) {
        return -1;
    }
    for (uint32_t i = 0; i < view->count; i++) {
        X509 *x509 = view->getter(view->ctx, i);
        if (x509 == NULL) {
            continue;
        }
        if (CheckCertBySpki(x509, cache, NULL) || CheckCertByAki(x509, cache, NULL)) {
            return (int32_t)i;
        }
    }
    return -1;
}

/* Phase 1+2: check staleness under the read lock (contention-free for the common
 * case) and only contend for the write lock when a refresh is needed. */
static void RefreshIfStale(RevocationSource src)
{
    const RevocationCache *cache = RevocationCacheAcquireRead(src);
    bool stale = RevocationCacheIsStale(cache);
    RevocationCacheReleaseRead(src);
    if (!stale) {
        return;
    }
    LOGI("revocation: cache stale, refresh, src=%d", (int32_t)src);
    RevocationCacheRefreshIfNeeded(src);
}

/* Phase 3: query a single source. Only takes the cert view; the read lock is
 * acquired and released entirely inside this function.
 * Returns CF_ERR_CRYPTO_OPERATION when the source cache is unavailable
 * (policy file missing/unreadable). */
static CfResult CheckCertsBySource(const RevocationCertView *view, RevocationSource src, int32_t *hitIndex)
{
    *hitIndex = -1;
    const RevocationCache *cache = RevocationCacheAcquireRead(src);
    if (cache == NULL) {
        RevocationCacheReleaseRead(src);
        if (src == REVOCATION_SOURCE_USER) {
            LOGW("revocation: user policy unavailable");
        } else {
            LOGW("revocation: cloud policy unavailable");
        }
        return CF_ERR_CRYPTO_OPERATION;
    }
    int32_t index = FindFirstHitByCache(view, cache);
    RevocationCacheReleaseRead(src);
    if (index < 0) {
        return CF_SUCCESS;
    }
    if (src == REVOCATION_SOURCE_USER) {
        LOGW("revocation: cert[%d] revoked by user policy", index);
    } else {
        LOGW("revocation: cert[%d] revoked by cloud policy", index);
    }
    *hitIndex = index;
    return CF_SUCCESS;
}

/* Shared flow for already-parsed certificates exposed through a view: refresh
 * caches on demand, then check the user cache first and fall back to the cloud
 * cache. A policy source whose file is missing/unreadable is treated as
 * unavailable; when neither source can be checked the policy is treated as
 * empty (not revoked) so that callers such as chain validation and CMS
 * verification keep working on devices where the policy files have not been
 * provisioned yet. */
static CfResult CheckParsedX509s(const RevocationCertView *view, int32_t *blockedIndex)
{
    RefreshIfStale(REVOCATION_SOURCE_CLOUD);
    RefreshIfStale(REVOCATION_SOURCE_USER);

    int32_t hitIndex = -1;
    CfResult userRes = CheckCertsBySource(view, REVOCATION_SOURCE_USER, &hitIndex);
    if (userRes == CF_SUCCESS && hitIndex >= 0) {
        if (blockedIndex != NULL) {
            *blockedIndex = hitIndex;
        }
        return CF_ERR_CERT_REVOKED;
    }

    int32_t cloudHitIndex = -1;
    CfResult cloudRes = CheckCertsBySource(view, REVOCATION_SOURCE_CLOUD, &cloudHitIndex);
    if (cloudRes == CF_SUCCESS && cloudHitIndex >= 0) {
        if (blockedIndex != NULL) {
            *blockedIndex = cloudHitIndex;
        }
        return CF_ERR_CERT_REVOKED;
    }
    if (userRes != CF_SUCCESS && cloudRes != CF_SUCCESS) {
        LOGW("revocation: both policy files missing/unavailable, treat as not revoked");
        if (blockedIndex != NULL) {
            *blockedIndex = -1;
        }
        return CF_SUCCESS;
    }
    LOGD("revocation: no cert matched, pass");
    if (blockedIndex != NULL) {
        *blockedIndex = -1;
    }
    return CF_SUCCESS;
}

CfResult RevocationCheck(const HcfX509CertificateArray *certs, int32_t *blockedIndex)
{
    if (blockedIndex != NULL) {
        *blockedIndex = -1;
    }
    if (certs == NULL || (certs->data == NULL && certs->count > 0)) {
        LOGE("revocation: invalid params, certs null or data null");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (certs->count == 0) {
        LOGD("revocation: empty chain, pass");
        return CF_SUCCESS;
    }
    LOGD("revocation: check start, cert count=%u", certs->count);

    X509 **x509s = NULL;
    uint32_t certCount = 0;
    if (!BuildX509Array(certs, &x509s, &certCount)) {
        LOGE("revocation: build x509 array failed, count=%u", certs->count);
        return CF_ERR_MALLOC;
    }
    const RevocationCertView view = { .ctx = x509s, .count = certCount, .getter = ArrayCertGetter };
    CfResult result = CheckParsedX509s(&view, blockedIndex);
    FreeX509Array(x509s, certCount);
    return result;
}

CfResult RevocationCheckX509(X509 **x509s, uint32_t count, int32_t *blockedIndex)
{
    if (blockedIndex != NULL) {
        *blockedIndex = -1;
    }
    if (x509s == NULL && count > 0) {
        LOGE("revocation: invalid x509 array, x509s null");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (count == 0) {
        LOGD("revocation: empty x509 array, pass");
        return CF_SUCCESS;
    }
    LOGD("revocation: check start (x509), cert count=%u", count);
    const RevocationCertView view = { .ctx = x509s, .count = count, .getter = ArrayCertGetter };
    return CheckParsedX509s(&view, blockedIndex);
}

CfResult RevocationCheckX509View(const void *ctx, uint32_t count,
    RevocationCertGetter getter, int32_t *blockedIndex)
{
    if (blockedIndex != NULL) {
        *blockedIndex = -1;
    }
    if (count == 0) {
        LOGD("revocation: empty x509 view, pass");
        return CF_SUCCESS;
    }
    if (getter == NULL) {
        LOGE("revocation: invalid x509 view, getter null");
        return CF_ERR_PARAMETER_CHECK;
    }
    LOGD("revocation: check start (view), cert count=%u", count);
    const RevocationCertView view = { .ctx = ctx, .count = count, .getter = getter };
    return CheckParsedX509s(&view, blockedIndex);
}

CfResult RevocationCheckX509Stack(STACK_OF(X509) *chain, int32_t *blockedIndex)
{
    if (blockedIndex != NULL) {
        *blockedIndex = -1;
    }
    if (chain == NULL) {
        LOGD("revocation: empty x509 stack, pass");
        return CF_SUCCESS;
    }
    int count = sk_X509_num(chain);
    if (count <= 0) {
        LOGD("revocation: empty x509 stack, pass");
        return CF_SUCCESS;
    }
    LOGD("revocation: check start (stack), cert count=%d", count);
    const RevocationCertView view = {
        .ctx = chain, .count = (uint32_t)count, .getter = StackCertGetter
    };
    return CheckParsedX509s(&view, blockedIndex);
}

void RevocationClearCache(void)
{
    RevocationCacheClearAll();
}

void RevocationNotifyUserCfgUpdate(void)
{
    RevocationCacheClearUser();
}
