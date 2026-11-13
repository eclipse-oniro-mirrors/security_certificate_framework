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

#ifndef REVOCATION_CACHE_H
#define REVOCATION_CACHE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA256 digest length in bytes; fixed hash length for type-1 rule matching. */
#define REVOCATION_HASH_LEN 32
/* AKI keyIdentifier length in bytes. Only 20-byte keyids (SHA-1 method) are
 * supported here; RFC 5280 allows other lengths, and certificates with a
 * non-20-byte keyid are skipped in the type-2 check (fail-open, known limit). */
#define REVOCATION_AKI_LEN 20
/* Maximum number of valid entries per policy file; extra entries are truncated
 * to bound memory usage against malformed files. */
#define REVOCATION_MAX_ENTRIES 10000
/* Maximum characters per policy file line (including newline); lines are split
 * by '\n' after fread, over-long lines are skipped. */
#define REVOCATION_MAX_LINE 256
/* Periodic refresh interval of the caches in seconds (12 hours), based on the
 * CLOCK_BOOTTIME monotonic clock. */
#define REVOCATION_REFRESH_INTERVAL (12 * 60 * 60)
/* Revocation policy directory (read-only). Files are written by the cloud push
 * module / cert manager module; this module only opens them for reading. */
#ifdef REVOCATION_TEST_CFG_DIR
#define REVOCATION_CFG_DIR REVOCATION_TEST_CFG_DIR
#else
#define REVOCATION_CFG_DIR \
    "/data/service/el1/public/for-all-app/cert_manager_service/certificates/revocation/forceCheck"
#endif
/* Cloud-pushed revocation policy file name (written by cloud push, read-only here). */
#define REVOCATION_CLOUD_CFG "certRevocationPolicy_cloud.cfg"
/* User disable policy file name (written by cert manager, read-only here). */
#define REVOCATION_USER_CFG "certRevocationPolicy_user.cfg"

/* ===== Date/time parsing constants ===== */

/* Length of a YYYYMMDD date string (e.g. "20260101"). */
#define REVOCATION_DATE_STR_LEN 8
/* Time-range date buffer length including the NUL terminator. */
#define REVOCATION_DATE_BUF_LEN 9
/* Default start date of a time range ("00000000" means no lower bound). */
#define REVOCATION_DATE_MIN_STR "00000000"
/* Default end date of a time range ("99999999" means no upper bound). */
#define REVOCATION_DATE_MAX_STR "99999999"
/* Numeric offset for hex letters a-f/A-F ('a' - 'a' + 10 = 10). */
#define REVOCATION_HEX_ALPHA_OFFSET 10
/* Number of hex characters per byte. */
#define REVOCATION_HEX_CHARS_PER_BYTE 2
/* Nibble shift (high 4 bits shifted right). */
#define REVOCATION_NIBBLE_SHIFT 4
/* Line type prefix length ("1," or "2,"). */
#define REVOCATION_LINE_TYPE_PREFIX_LEN 2
/* Two-digit UTCTime years >= 50 map to 19xx (e.g. "50" -> 1950), per RFC 5280. */
#define REVOCATION_YEAR_BASE_1900 1900
/* Two-digit UTCTime years < 50 map to 20xx (e.g. "26" -> 2026), per RFC 5280. */
#define REVOCATION_YEAR_BASE_2000 2000
/* Threshold separating 19xx and 20xx two-digit UTCTime years. */
#define REVOCATION_UTCTIME_YEAR_THRESHOLD 50
/* ASN.1 UTCTime length (e.g. "260101120000Z", YYMMDDHHMMSSZ); used for
 * notBefore values in [1950, 2049]. */
#define REVOCATION_UTCTIME_LEN 13
/* ASN.1 GeneralizedTime length (e.g. "20260101120000Z", YYYYMMDDHHMMSSZ);
 * used for notBefore values in [2050, ...]. */
#define REVOCATION_GENERALIZEDTIME_LEN 15
/* Decimal base for manual digit accumulation (v = v * 10 + digit). */
#define REVOCATION_DECIMAL_BASE 10
/* Divisor to split month/day from a YYYYMMDD value:
 * month = (v / 100) % 100, day = v % 100. */
#define REVOCATION_MONTH_DAY_DIVISOR 100
/* Multiplier to compose a YYYYMMDD value: out = year * 10000 + month * 100 + day. */
#define REVOCATION_YEAR_MONTH_DIVISOR 10000

/* ===== Buffer size constants ===== */

/* AKI hex string buffer size: 20-byte AKI = 40 hex chars + NUL. */
#define REVOCATION_AKI_HEX_LEN 41
/* Time segment parse buffer size: "YYYYMMDD-YYYYMMDD" is at most 17 chars + NUL,
 * 64 leaves headroom. */
#define REVOCATION_TIME_SEG_BUF_SIZE 64

typedef struct {
    char startDate[REVOCATION_DATE_BUF_LEN];
    char endDate[REVOCATION_DATE_BUF_LEN];
} RevocationTimeRange;

typedef struct {
    uint8_t aki[REVOCATION_AKI_LEN];
    uint32_t rangeCount;
    RevocationTimeRange *ranges;
} RevocationAkiEntry;

typedef struct {
    uint32_t spkiCount;
    uint8_t (*spkiHashes)[REVOCATION_HASH_LEN];
    uint32_t akiCount;
    RevocationAkiEntry *akiEntries;
    uint8_t fileDigest[REVOCATION_HASH_LEN];
    uint64_t lastCheckBootTime;
} RevocationCache;

typedef enum {
    REVOCATION_SOURCE_CLOUD = 0,
    REVOCATION_SOURCE_USER = 1,
    REVOCATION_SOURCE_BUTT,
} RevocationSource;

/* Phase 1/3: acquire the read lock and return the current cache pointer
 * (may be NULL). The pointer is valid until RevocationCacheReleaseRead.
 * Returns NULL without locking when src is invalid. */
const RevocationCache *RevocationCacheAcquireRead(RevocationSource src);

/* Phase 1/3: release the read lock. Must pair with a successful
 * RevocationCacheAcquireRead call. */
void RevocationCacheReleaseRead(RevocationSource src);

/* Phase 1: whether the cache needs a refresh (not loaded / refresh interval
 * elapsed / clock error). Recommended to call while holding the read lock. */
bool RevocationCacheIsStale(const RevocationCache *cache);

/* Phase 2: refresh on demand. Takes the write lock and re-checks staleness
 * (double-check to avoid duplicate refreshes) before loading/rebuilding.
 * Lock acquisition and release both complete inside the function.
 * A missing/unreadable policy file leaves the cache NULL; callers detect this
 * via RevocationCacheAcquireRead returning NULL. */
void RevocationCacheRefreshIfNeeded(RevocationSource src);

/* Clear both cloud and user caches; the next query lazily reloads them. */
void RevocationCacheClearAll(void);

/* Clear only the user cache; the cloud cache is untouched. */
void RevocationCacheClearUser(void);

/* Binary-search the SPKI SHA256 in the cache snapshot.
 * Returns false when cache is NULL or empty (fail-open: treated as not revoked). */
bool RevocationCacheMatchSpki(const RevocationCache *cache, const uint8_t *sha256);

/* Binary-search the AKI and then match the notBefore date against time ranges.
 * Returns false when cache is NULL or empty (fail-open: treated as not revoked).
 * notBeforeDate is a YYYYMMDD string (9 bytes including NUL), compared by strcmp.
 * startDate/endDate are date strings from the policy file; "00000000" means no
 * lower bound and "99999999" means no upper bound. */
bool RevocationCacheMatchAki(const RevocationCache *cache, const uint8_t *aki, const char *notBeforeDate);

#ifdef __cplusplus
}
#endif

#endif // REVOCATION_CACHE_H
