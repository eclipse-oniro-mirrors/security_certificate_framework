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

#include "revocation_cache.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "revocation_event_subscriber.h"
#include "securec.h"

#include "openssl/sha.h"

typedef struct {
    RevocationCache *cachePtr; /* current cache object, NULL means unavailable (file missing/unreadable) */
    const char *cfgPath;
    pthread_rwlock_t lock;
} CacheCtx;

/* Global cache contexts (one per source). cachePtr starts as NULL (not loaded);
 * cfgPath and lock are statically initialized. Callers select the context by src. */
static CacheCtx g_cloudCache = { NULL, REVOCATION_CFG_DIR "/" REVOCATION_CLOUD_CFG, PTHREAD_RWLOCK_INITIALIZER };
static CacheCtx g_userCache = { NULL, REVOCATION_CFG_DIR "/" REVOCATION_USER_CFG, PTHREAD_RWLOCK_INITIALIZER };
static pthread_mutex_t g_eventSubLock = PTHREAD_MUTEX_INITIALIZER;
static bool g_eventSubscribed = false;

/* Auto-subscribe to CA status change events on first use (once per process, mutex-guarded) */
static void EnsureEventSubscribed(void)
{
    if (g_eventSubscribed) {
        return;
    }
    pthread_mutex_lock(&g_eventSubLock);
    if (g_eventSubscribed) {
        pthread_mutex_unlock(&g_eventSubLock);
        return;
    }
    if (RevocationEventSubscribe() == 0) {
        g_eventSubscribed = true;
    } else {
        LOGW("revocation: failed to subscribe CA status events, will retry");
    }
    pthread_mutex_unlock(&g_eventSubLock);
}

#define REVOCATION_CLOCK_FAIL_SENTINEL ((uint64_t)(-1))

static uint64_t GetBootTimeSec(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
        LOGW("revocation: clock_gettime CLOCK_BOOTTIME failed, force refresh");
        return REVOCATION_CLOCK_FAIL_SENTINEL;
    }
    return (uint64_t)ts.tv_sec;
}

/* Securely zero memory before freeing to avoid leaving policy data behind. */
static void SecureZeroize(void *ptr, size_t size)
{
    if (ptr != NULL && size > 0) {
        (void)memset_s(ptr, size, 0, size);
    }
}

static void FreeRevocationCache(RevocationCache *cache)
{
    if (cache == NULL) {
        return;
    }
    if (cache->spkiHashes != NULL) {
        SecureZeroize(cache->spkiHashes, (size_t)cache->spkiCount * REVOCATION_HASH_LEN);
        CF_FREE_PTR(cache->spkiHashes);
    }
    if (cache->akiEntries != NULL) {
        for (uint32_t i = 0; i < cache->akiCount; i++) {
            SecureZeroize(cache->akiEntries[i].ranges,
                (size_t)cache->akiEntries[i].rangeCount * sizeof(RevocationTimeRange));
            CF_FREE_PTR(cache->akiEntries[i].ranges);
        }
        SecureZeroize(cache->akiEntries, (size_t)cache->akiCount * sizeof(RevocationAkiEntry));
        CF_FREE_PTR(cache->akiEntries);
    }
    SecureZeroize(cache, sizeof(RevocationCache));
    CF_FREE_PTR(cache);
}

static bool HexCharToVal(char c, uint8_t *out)
{
    if (c >= '0' && c <= '9') {
        *out = (uint8_t)(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        *out = (uint8_t)(c - 'a' + REVOCATION_HEX_ALPHA_OFFSET);
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        *out = (uint8_t)(c - 'A' + REVOCATION_HEX_ALPHA_OFFSET);
        return true;
    }
    LOGW("revocation: hex char 0x%02x invalid", (uint32_t)(uint8_t)c);
    return false;
}

static bool HexDecode(const char *hex, uint8_t *out, uint32_t expectBytes)
{
    uint32_t hexLen = (uint32_t)strlen(hex);
    if (hexLen != expectBytes * REVOCATION_HEX_CHARS_PER_BYTE) {
        LOGW("revocation: hex length=%u, expect=%u, skip",
            hexLen, expectBytes * REVOCATION_HEX_CHARS_PER_BYTE);
        return false;
    }
    for (uint32_t i = 0; i < expectBytes; i++) {
        uint8_t hi;
        uint8_t lo;
        if (!HexCharToVal(hex[i * REVOCATION_HEX_CHARS_PER_BYTE], &hi) ||
            !HexCharToVal(hex[i * REVOCATION_HEX_CHARS_PER_BYTE + 1], &lo)) {
            return false;
        }
        out[i] = (uint8_t)((hi << REVOCATION_NIBBLE_SHIFT) | lo);
    }
    return true;
}

static int CmpSpkiHash(const void *a, const void *b)
{
    return memcmp(a, b, REVOCATION_HASH_LEN);
}

static int CmpAkiEntry(const void *a, const void *b)
{
    const RevocationAkiEntry *ea = (const RevocationAkiEntry *)a;
    const RevocationAkiEntry *eb = (const RevocationAkiEntry *)b;
    return memcmp(ea->aki, eb->aki, REVOCATION_AKI_LEN);
}

static int CmpAkiKey(const void *key, const void *element)
{
    const uint8_t *akiKey = (const uint8_t *)key;
    const RevocationAkiEntry *entry = (const RevocationAkiEntry *)element;
    return memcmp(akiKey, entry->aki, REVOCATION_AKI_LEN);
}

static int DetectLineType(const char *line, uint32_t lineLen)
{
    if (lineLen < REVOCATION_LINE_TYPE_PREFIX_LEN) {
        return 0;
    }
    if (line[0] == '1' && line[1] == ',') {
        return 1;
    }
    if (line[0] == '2' && line[1] == ',') {
        return 2;
    }
    return 0;
}

static void StripLineEnd(char *line)
{
    uint32_t len = (uint32_t)strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
}

static bool ParseSpkiHashLine(const char *content, uint8_t *hashOut)
{
    return HexDecode(content, hashOut, REVOCATION_HASH_LEN);
}

static uint32_t CountTimeRanges(const char *fields)
{
    uint32_t count = 0;
    const char *p = fields;
    while (*p != '\0') {
        const char *comma = strchr(p, ',');
        if (comma != NULL) {
            count++;
            p = comma + 1;
        } else {
            count++;
            break;
        }
    }
    return count;
}

/* Validate an 8-digit date segment (YYYYMMDD); empty segments (len == 0) are
 * handled by the caller as default bounds. */
static bool IsValidDateStr(const char *str, uint32_t len)
{
    if (len != REVOCATION_DATE_STR_LEN) {
        return false;
    }
    for (uint32_t i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
    }
    return true;
}

static bool ParseOneTimeRange(const char *seg, RevocationTimeRange *range)
{
    if (strcpy_s(range->startDate, REVOCATION_DATE_BUF_LEN, REVOCATION_DATE_MIN_STR) != EOK) {
        return false;
    }
    if (strcpy_s(range->endDate, REVOCATION_DATE_BUF_LEN, REVOCATION_DATE_MAX_STR) != EOK) {
        return false;
    }
    const char *dash = strchr(seg, '-');
    if (dash == NULL) {
        LOGW("revocation: time segment [%s] has no dash, skip", seg);
        return false;
    }
    uint32_t segLen = (uint32_t)strlen(seg);
    uint32_t beforeDash = (uint32_t)(dash - seg);
    uint32_t afterDash = segLen - beforeDash - 1;
    if (beforeDash > 0) {
        if (!IsValidDateStr(seg, beforeDash)) {
            LOGW("revocation: start date len=%u not YYYYMMDD digits, skip", beforeDash);
            return false;
        }
        if (memcpy_s(range->startDate, REVOCATION_DATE_BUF_LEN, seg, beforeDash) != EOK) {
            LOGW("revocation: memcpy_s start date failed, skip");
            return false;
        }
        range->startDate[beforeDash] = '\0';
    }
    if (afterDash > 0) {
        if (!IsValidDateStr(dash + 1, afterDash)) {
            LOGW("revocation: end date len=%u not YYYYMMDD digits, skip", afterDash);
            return false;
        }
        if (memcpy_s(range->endDate, REVOCATION_DATE_BUF_LEN, dash + 1, afterDash) != EOK) {
            LOGW("revocation: memcpy_s end date failed, skip");
            return false;
        }
        range->endDate[afterDash] = '\0';
    }
    if (strcmp(range->startDate, range->endDate) > 0) {
        LOGW("revocation: start=%s > end=%s, skip", range->startDate, range->endDate);
        return false;
    }
    return true;
}

static bool ParseAkiHexField(const char *content, uint8_t *akiOut, const char **fieldsOut)
{
    const char *firstComma = strchr(content, ',');
    if (firstComma == NULL) {
        LOGW("revocation: type2 line has no comma after AKI, skip");
        return false;
    }
    uint32_t akiHexLen = (uint32_t)(firstComma - content);
    char akiHex[REVOCATION_AKI_HEX_LEN];
    if (akiHexLen >= sizeof(akiHex)) {
        LOGW("revocation: AKI hex too long=%u, skip", akiHexLen);
        return false;
    }
    if (memcpy_s(akiHex, sizeof(akiHex), content, akiHexLen) != EOK) {
        LOGW("revocation: memcpy_s AKI hex failed, skip");
        return false;
    }
    akiHex[akiHexLen] = '\0';
    if (!HexDecode(akiHex, akiOut, REVOCATION_AKI_LEN)) {
        return false;
    }
    *fieldsOut = firstComma + 1;
    return true;
}

static uint32_t FillTimeRanges(const char *fields, RevocationTimeRange *ranges, uint32_t maxCount)
{
    uint32_t validCount = 0;
    const char *p = fields;
    while (*p != '\0' && validCount < maxCount) {
        char segBuf[REVOCATION_TIME_SEG_BUF_SIZE];
        const char *comma = strchr(p, ',');
        uint32_t segLen = (comma != NULL) ? (uint32_t)(comma - p) : (uint32_t)strlen(p);
        if (segLen == 0 || segLen >= sizeof(segBuf)) {
            LOGW("revocation type2 empty or too long time segment, skip");
            if (comma == NULL) {
                break;
            }
            p = comma + 1;
            continue;
        }
        if (memcpy_s(segBuf, sizeof(segBuf), p, segLen) != EOK) {
            LOGW("revocation: memcpy_s time segment failed, skip");
            if (comma == NULL) {
                break;
            }
            p = comma + 1;
            continue;
        }
        segBuf[segLen] = '\0';
        if (ParseOneTimeRange(segBuf, &ranges[validCount])) {
            validCount++;
        }
        if (comma == NULL) {
            break;
        }
        p = comma + 1;
    }
    return validCount;
}

static bool ParseAkiRangeLine(const char *content, RevocationAkiEntry *entry)
{
    const char *fields = NULL;
    if (!ParseAkiHexField(content, entry->aki, &fields)) {
        return false;
    }
    uint32_t rangeCount = CountTimeRanges(fields);
    if (rangeCount == 0) {
        LOGW("revocation: type2 line has no time ranges, skip");
        return false;
    }
    RevocationTimeRange *ranges = (RevocationTimeRange *)CfMalloc(
        rangeCount * sizeof(RevocationTimeRange), 0);
    if (ranges == NULL) {
        LOGE("revocation: malloc time ranges failed, count=%u", rangeCount);
        return false;
    }
    uint32_t validCount = FillTimeRanges(fields, ranges, rangeCount);
    if (validCount == 0) {
        LOGW("revocation: type2 line has no valid time ranges after parse, skip");
        CF_FREE_PTR(ranges);
        return false;
    }
    entry->rangeCount = validCount;
    entry->ranges = ranges;
    return true;
}

static bool ReadFileToMemory(const char *path, uint8_t **outBuf, uint32_t *outLen)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        LOGW("revocation: stat [%s] failed, file may not exist", path);
        return false;
    }
    if (st.st_size <= 0) {
        LOGW("revocation: file [%s] is empty", path);
        *outBuf = NULL;
        *outLen = 0;
        return true;
    }
    if ((uint64_t)st.st_size > (uint64_t)REVOCATION_MAX_ENTRIES * REVOCATION_MAX_LINE) {
        LOGW("revocation: file [%s] size=%lld exceeds limit", path, (long long)st.st_size);
        return false;
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        LOGW("revocation: fopen [%s] failed", path);
        return false;
    }
    uint8_t *buf = (uint8_t *)CfMalloc((uint32_t)st.st_size, 0);
    if (buf == NULL) {
        LOGE("revocation: malloc file buf failed, size=%lld", (long long)st.st_size);
        fclose(fp);
        return false;
    }
    size_t totalRead = fread(buf, 1, (size_t)st.st_size, fp);
    if (ferror(fp) || totalRead != (size_t)st.st_size) {
        LOGW("revocation: fread %zu/%lld for [%s]", totalRead, (long long)st.st_size, path);
        CF_FREE_PTR(buf);
        fclose(fp);
        return false;
    }
    fclose(fp);
    *outBuf = buf;
    *outLen = (uint32_t)totalRead;
    return true;
}

/* Compute the content digest. A NULL buf means an empty file; the empty-content
 * digest keeps the 12h refresh comparison path consistent. */
static void ComputeBufDigest(const uint8_t *buf, uint32_t bufLen, uint8_t *digestOut)
{
    if (buf != NULL) {
        SHA256(buf, bufLen, digestOut);
    } else {
        SHA256((const uint8_t *)"", 0, digestOut);
    }
}

static uint32_t ParseOneSpkiLine(uint8_t (*hashes)[REVOCATION_HASH_LEN], uint32_t idx, uint32_t max,
    const char *line, uint32_t *total)
{
    if (idx >= max) {
        LOGW("revocation type1 idx=%u >= max=%u, skip", idx, max);
        return 0;
    }
    if (!ParseSpkiHashLine(line + REVOCATION_LINE_TYPE_PREFIX_LEN, hashes[idx])) {
        return 0;
    }
    (*total)++;
    return 1;
}

static uint32_t ParseOneAkiLine(RevocationAkiEntry *entries, uint32_t idx, uint32_t max,
    const char *line, uint32_t *total)
{
    if (idx >= max) {
        LOGW("revocation type2 idx=%u >= max=%u, skip", idx, max);
        return 0;
    }
    RevocationAkiEntry entry = { {0}, 0, NULL };
    if (!ParseAkiRangeLine(line + REVOCATION_LINE_TYPE_PREFIX_LEN, &entry)) {
        return 0;
    }
    if (memcpy_s(entries[idx].aki, REVOCATION_AKI_LEN, entry.aki, REVOCATION_AKI_LEN) != EOK) {
        LOGE("revocation: memcpy_s aki failed at idx=%u", idx);
        if (entry.ranges != NULL) {
            CF_FREE_PTR(entry.ranges);
        }
        return 0;
    }
    entries[idx].rangeCount = entry.rangeCount;
    entries[idx].ranges = entry.ranges;
    (*total)++;
    return 1;
}

/* Deduplicate sorted spkiHashes in-place (adjacent duplicates). Returns new count. */
static uint32_t DedupSortedSpki(uint8_t (*hashes)[REVOCATION_HASH_LEN], uint32_t count)
{
    if (count <= 1) {
        return count;
    }
    uint32_t write = 1;
    for (uint32_t read = 1; read < count; read++) {
        if (memcmp(hashes[read], hashes[read - 1], REVOCATION_HASH_LEN) != 0) {
            if (write != read) {
                (void)memcpy_s(hashes[write], REVOCATION_HASH_LEN, hashes[read], REVOCATION_HASH_LEN);
            }
            write++;
        }
    }
    if (write < count) {
        LOGW("revocation type1 removed %u duplicate hashes", count - write);
    }
    return write;
}

/* Deduplicate sorted akiEntries in-place (adjacent duplicates by AKI). Returns new count. */
static uint32_t DedupSortedAki(RevocationAkiEntry *entries, uint32_t count)
{
    if (count <= 1) {
        return count;
    }
    uint32_t write = 1;
    for (uint32_t read = 1; read < count; read++) {
        if (memcmp(entries[read].aki, entries[read - 1].aki, REVOCATION_AKI_LEN) != 0) {
            if (write != read) {
                entries[write] = entries[read];
            }
            write++;
        } else {
            LOGW("revocation type2 removed duplicate AKI at index %u", read);
            SecureZeroize(entries[read].ranges,
                (size_t)entries[read].rangeCount * sizeof(RevocationTimeRange));
            CF_FREE_PTR(entries[read].ranges);
        }
    }
    return write;
}

static RevocationCache *AllocCacheArrays(RevocationCache *cache, uint32_t spkiCount, uint32_t akiCount)
{
    if (spkiCount > 0) {
        cache->spkiHashes = (uint8_t(*)[REVOCATION_HASH_LEN])CfMalloc(
            spkiCount * sizeof(uint8_t[REVOCATION_HASH_LEN]), 0);
        if (cache->spkiHashes == NULL) {
            LOGE("revocation: malloc spkiHashes failed, count=%u", spkiCount);
            CF_FREE_PTR(cache);
            return NULL;
        }
    }
    if (akiCount > 0) {
        cache->akiEntries = (RevocationAkiEntry *)CfMalloc(
            akiCount * sizeof(RevocationAkiEntry), 0);
        if (cache->akiEntries == NULL) {
            LOGE("revocation: malloc akiEntries failed, count=%u", akiCount);
            if (cache->spkiHashes != NULL) {
                CF_FREE_PTR(cache->spkiHashes);
            }
            CF_FREE_PTR(cache);
            return NULL;
        }
    }
    return cache;
}

/* Iterate policy file content line by line: split by '\n', skip over-long lines,
 * strip line endings, then invoke the handler. The handler returns true when the
 * line produced a valid entry and increments total; iteration stops once total
 * reaches maxEntries (bounds memory against malformed files). */
typedef bool (*RevocationLineHandler)(const char *line, uint32_t *total, void *arg);

static void ForEachCfgLine(const uint8_t *buf, uint32_t bufLen, uint32_t maxEntries,
    RevocationLineHandler handler, void *arg)
{
    char line[REVOCATION_MAX_LINE];
    uint32_t total = 0;
    uint32_t lineStart = 0;
    for (uint32_t i = 0; i <= bufLen && total < maxEntries; i++) {
        if (i < bufLen && buf[i] != '\n') {
            continue;
        }
        uint32_t lineLen = i - lineStart;
        if (lineLen > 0 && lineLen < sizeof(line)) {
            if (memcpy_s(line, sizeof(line), buf + lineStart, lineLen) == EOK) {
                line[lineLen] = '\0';
                StripLineEnd(line);
                (void)handler(line, &total, arg);
            }
        } else if (lineLen >= sizeof(line)) {
            LOGW("revocation cfg line too long (%u bytes), skip", lineLen);
        }
        lineStart = i + 1;
    }
    if (total >= maxEntries) {
        LOGW("revocation cfg entries exceed %u, truncated", maxEntries);
    }
}

typedef struct {
    uint32_t spkiCount;
    uint32_t akiCount;
} CountLinesCtx;

static bool CountLineHandler(const char *line, uint32_t *total, void *arg)
{
    CountLinesCtx *ctx = (CountLinesCtx *)arg;
    int type = DetectLineType(line, (uint32_t)strlen(line));
    if (type == 1) {
        ctx->spkiCount++;
        (*total)++;
        return true;
    }
    if (type == 2) {
        ctx->akiCount++;
        (*total)++;
        return true;
    }
    return false;
}

typedef struct {
    RevocationCache *cache;
    uint32_t t1Max;
    uint32_t t2Max;
    uint32_t t1Idx;
    uint32_t t2Idx;
} ParseLinesCtx;

static bool ParseLineHandler(const char *line, uint32_t *total, void *arg)
{
    ParseLinesCtx *ctx = (ParseLinesCtx *)arg;
    int type = DetectLineType(line, (uint32_t)strlen(line));
    if (type == 1) {
        ctx->t1Idx += ParseOneSpkiLine(ctx->cache->spkiHashes, ctx->t1Idx, ctx->t1Max, line, total);
        return true;
    }
    if (type == 2) {
        ctx->t2Idx += ParseOneAkiLine(ctx->cache->akiEntries, ctx->t2Idx, ctx->t2Max, line, total);
        return true;
    }
    if (line[0] != '\0') {
        LOGW("revocation cfg unknown type line, skip");
    }
    return false;
}

static RevocationCache *CreateEmptyCache(void)
{
    RevocationCache *empty = (RevocationCache *)CfMalloc(sizeof(RevocationCache), 0);
    if (empty == NULL) {
        LOGE("revocation: malloc empty cache failed");
        return NULL;
    }
    empty->lastCheckBootTime = GetBootTimeSec();
    return empty;
}

static RevocationCache *LoadCacheFromBuf(const char *path, uint8_t *buf, uint32_t bufLen)
{
    CountLinesCtx countCtx = { 0, 0 };
    ForEachCfgLine(buf, bufLen, REVOCATION_MAX_ENTRIES, CountLineHandler, &countCtx);
    uint32_t spkiCount = countCtx.spkiCount;
    uint32_t akiCount = countCtx.akiCount;
    if (spkiCount == 0 && akiCount == 0) {
        LOGW("revocation cfg [%s] loaded empty", path);
        return CreateEmptyCache();
    }
    RevocationCache *cache = (RevocationCache *)CfMalloc(sizeof(RevocationCache), 0);
    if (cache == NULL) {
        LOGE("revocation: malloc cache failed");
        return NULL;
    }
    cache = AllocCacheArrays(cache, spkiCount, akiCount);
    if (cache == NULL) {
        LOGE("revocation: alloc cache arrays failed, spki=%u aki=%u", spkiCount, akiCount);
        return NULL;
    }
    ParseLinesCtx parseCtx = { cache, spkiCount, akiCount, 0, 0 };
    ForEachCfgLine(buf, bufLen, REVOCATION_MAX_ENTRIES, ParseLineHandler, &parseCtx);
    cache->spkiCount = parseCtx.t1Idx;
    cache->akiCount = parseCtx.t2Idx;
    if (cache->spkiCount > 1) {
        qsort(cache->spkiHashes, cache->spkiCount, sizeof(uint8_t[REVOCATION_HASH_LEN]), CmpSpkiHash);
        cache->spkiCount = DedupSortedSpki(cache->spkiHashes, cache->spkiCount);
    }
    if (cache->akiCount > 1) {
        qsort(cache->akiEntries, cache->akiCount, sizeof(RevocationAkiEntry), CmpAkiEntry);
        cache->akiCount = DedupSortedAki(cache->akiEntries, cache->akiCount);
    }
    LOGI("revocation cfg [%s] loaded: spki=%u, aki=%u", path, cache->spkiCount, cache->akiCount);
    return cache;
}

/* Build a cache and record the file digest and timestamp. A non-NULL buf is used
 * directly (the caller keeps ownership); a NULL buf means the file is read and
 * freed internally. An empty file (0 bytes) is valid and yields a 0-rule cache.
 * Returns NULL only when the file is missing/unreadable (retried on next call). */
static RevocationCache *LoadCacheFile(const char *path, uint8_t *buf, uint32_t bufLen)
{
    bool bufFromCaller = (buf != NULL);
    if (!bufFromCaller && !ReadFileToMemory(path, &buf, &bufLen)) {
        LOGW("revocation: failed to read cache file [%s], will retry later", path);
        return NULL;
    }
    RevocationCache *cache = LoadCacheFromBuf(path, buf, bufLen);
    if (cache != NULL) {
        ComputeBufDigest(buf, bufLen, cache->fileDigest);
        cache->lastCheckBootTime = GetBootTimeSec();
    }
    if (!bufFromCaller) {
        CF_FREE_PTR(buf);
    }
    return cache;
}

static bool NeedRefresh(const RevocationCache *cur)
{
    if (cur == NULL || cur->lastCheckBootTime == 0) {
        return true;
    }
    uint64_t now = GetBootTimeSec();
    if (now == REVOCATION_CLOCK_FAIL_SENTINEL || cur->lastCheckBootTime == REVOCATION_CLOCK_FAIL_SENTINEL) {
        return true;
    }
    if (now - cur->lastCheckBootTime >= REVOCATION_REFRESH_INTERVAL) {
        return true;
    }
    return false;
}

/* Unified refresh for both cloud and user: read file once, compute digest and
 * compare, reload from the same buf if changed.
 * File missing → free old, return NULL (retry next call). */
static RevocationCache *RefreshCache(RevocationCache *cur, const char *cfgPath)
{
    uint8_t *buf = NULL;
    uint32_t bufLen = 0;
    if (!ReadFileToMemory(cfgPath, &buf, &bufLen)) {
        LOGW("revocation: failed to read cache file [%s], will retry later", cfgPath);
        FreeRevocationCache(cur);
        return NULL;
    }
    uint8_t newDigest[REVOCATION_HASH_LEN];
    ComputeBufDigest(buf, bufLen, newDigest);
    if (memcmp(cur->fileDigest, newDigest, REVOCATION_HASH_LEN) == 0) {
        cur->lastCheckBootTime = GetBootTimeSec();
        LOGI("revocation: cache file [%s] unchanged, no reload needed", cfgPath);
        CF_FREE_PTR(buf);
        return cur;
    }
    RevocationCache *fresh = LoadCacheFile(cfgPath, buf, bufLen);
    FreeRevocationCache(cur);
    CF_FREE_PTR(buf);
    return fresh;
}

/* Phase 1/3: acquire the read lock and return the current cache pointer
 * (may be NULL). The pointer is valid until RevocationCacheReleaseRead.
 * Returns NULL without locking when src is invalid (caller must not release). */
const RevocationCache *RevocationCacheAcquireRead(RevocationSource src)
{
    CacheCtx *ctx = NULL;
    if (src == REVOCATION_SOURCE_CLOUD) {
        ctx = &g_cloudCache;
    } else if (src == REVOCATION_SOURCE_USER) {
        ctx = &g_userCache;
    } else {
        return NULL;
    }
    EnsureEventSubscribed();
    pthread_rwlock_rdlock(&ctx->lock);
    return ctx->cachePtr;
}

/* Phase 1/3: release the read lock. Must pair with a successful
 * RevocationCacheAcquireRead call. */
void RevocationCacheReleaseRead(RevocationSource src)
{
    CacheCtx *ctx = NULL;
    if (src == REVOCATION_SOURCE_CLOUD) {
        ctx = &g_cloudCache;
    } else if (src == REVOCATION_SOURCE_USER) {
        ctx = &g_userCache;
    } else {
        return;
    }
    pthread_rwlock_unlock(&ctx->lock);
}

/* Phase 1: whether the cache needs a refresh (not loaded / refresh interval
 * elapsed / clock error). Recommended to call while holding the read lock. */
bool RevocationCacheIsStale(const RevocationCache *cache)
{
    return NeedRefresh(cache);
}

/* Phase 2: refresh on demand. Only contends for the write lock when a refresh is
 * needed; re-checks staleness after acquiring it (double-check to avoid duplicate
 * refreshes). Both lock operations complete inside this function.
 * A missing/unreadable policy file leaves the cache NULL; the check layer
 * treats an unavailable policy as empty (not revoked). */
void RevocationCacheRefreshIfNeeded(RevocationSource src)
{
    CacheCtx *ctx = NULL;
    if (src == REVOCATION_SOURCE_CLOUD) {
        ctx = &g_cloudCache;
    } else if (src == REVOCATION_SOURCE_USER) {
        ctx = &g_userCache;
    } else {
        return;
    }
    pthread_rwlock_wrlock(&ctx->lock);
    if (NeedRefresh(ctx->cachePtr)) {
        RevocationCache *fresh = NULL;
        if (ctx->cachePtr != NULL) {
            fresh = RefreshCache(ctx->cachePtr, ctx->cfgPath);
        } else {
            fresh = LoadCacheFile(ctx->cfgPath, NULL, 0);
        }
        ctx->cachePtr = fresh;
    }
    pthread_rwlock_unlock(&ctx->lock);
}

static void ClearCacheCtx(CacheCtx *ctx)
{
    pthread_rwlock_wrlock(&ctx->lock);
    RevocationCache *old = ctx->cachePtr;
    ctx->cachePtr = NULL;
    pthread_rwlock_unlock(&ctx->lock);
    FreeRevocationCache(old);
}

void RevocationCacheClearAll(void)
{
    ClearCacheCtx(&g_cloudCache);
    ClearCacheCtx(&g_userCache);
}

void RevocationCacheClearUser(void)
{
    ClearCacheCtx(&g_userCache);
}

void RevocationCacheClearCloud(void)
{
    ClearCacheCtx(&g_cloudCache);
}

bool RevocationCacheMatchSpki(const RevocationCache *cache, const uint8_t *sha256)
{
    if (cache == NULL || cache->spkiCount == 0 || cache->spkiHashes == NULL) {
        return false;
    }
    void *found = bsearch(sha256, cache->spkiHashes, cache->spkiCount,
        sizeof(uint8_t[REVOCATION_HASH_LEN]), CmpSpkiHash);
    return found != NULL;
}

bool RevocationCacheMatchAki(const RevocationCache *cache, const uint8_t *aki, const char *notBeforeDate)
{
    if (cache == NULL || cache->akiCount == 0 || cache->akiEntries == NULL) {
        return false;
    }
    RevocationAkiEntry *entry = (RevocationAkiEntry *)bsearch(aki, cache->akiEntries,
        cache->akiCount, sizeof(RevocationAkiEntry), CmpAkiKey);
    if (entry == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < entry->rangeCount; i++) {
        RevocationTimeRange *r = &entry->ranges[i];
        if (strcmp(notBeforeDate, r->startDate) >= 0 && strcmp(notBeforeDate, r->endDate) <= 0) {
            return true;
        }
    }
    return false;
}
