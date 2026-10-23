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

#include "revocation_cache_mock.h"

#include <securec.h>

#include "cf_log.h"
#include "cf_memory.h"

/* The framework's RevocationCacheStore/RevocationCacheQuery are defined in
 * x509_cert_chain_validator_openssl_private.c and normally call the cert manager
 * CmSaveRevocationCache/CmGetRevocationCache IPC. In the unit-test process that IPC
 * is unavailable / rejects the caller, so --wrap redirects the calls here and the
 * revocation data is kept in an in-process in-memory cache keyed by (identifier, type).
 */

#define MOCK_CACHE_MAX_ENTRIES 8

typedef struct MockCacheEntry {
    char identifier[MAX_REVOCATION_CACHE_ID_LEN];
    HcfRevocationType type;
    uint8_t *data;
    uint32_t size;
    bool valid;
} MockCacheEntry;

static MockCacheEntry g_mockCache[MOCK_CACHE_MAX_ENTRIES];
static bool g_mockStoreCalled = false;
static bool g_mockQueryHit = false;

void RevocationCacheMockReset(void)
{
    for (int i = 0; i < MOCK_CACHE_MAX_ENTRIES; i++) {
        if (g_mockCache[i].data != NULL) {
            CfFree(g_mockCache[i].data);
        }
        (void)memset_s(&g_mockCache[i], sizeof(g_mockCache[i]), 0, sizeof(g_mockCache[i]));
    }
    g_mockStoreCalled = false;
    g_mockQueryHit = false;
}

bool RevocationCacheMockStoreCalled(void)
{
    return g_mockStoreCalled;
}

bool RevocationCacheMockQueryHit(void)
{
    return g_mockQueryHit;
}

static MockCacheEntry *FindEntry(const char *identifier, HcfRevocationType type)
{
    if (identifier == NULL) {
        return NULL;
    }
    for (int i = 0; i < MOCK_CACHE_MAX_ENTRIES; i++) {
        if (g_mockCache[i].valid && g_mockCache[i].type == type &&
            strncmp(g_mockCache[i].identifier, identifier, MAX_REVOCATION_CACHE_ID_LEN - 1) == 0) {
            return &g_mockCache[i];
        }
    }
    return NULL;
}

static MockCacheEntry *FindOrCreateEntry(const char *identifier, HcfRevocationType type)
{
    MockCacheEntry *entry = FindEntry(identifier, type);
    if (entry != NULL) {
        return entry;
    }
    for (int i = 0; i < MOCK_CACHE_MAX_ENTRIES; i++) {
        if (!g_mockCache[i].valid) {
            return &g_mockCache[i];
        }
    }
    return NULL;
}

static CfResult StoreToMockCache(const char *identifier, HcfRevocationType type, const CfBlob *data)
{
    if (identifier == NULL || data == NULL || data->data == NULL || data->size == 0) {
        return CF_ERR_PARAMETER_CHECK;
    }
    MockCacheEntry *entry = FindOrCreateEntry(identifier, type);
    if (entry == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *copy = (uint8_t *)CfMalloc(data->size, 0);
    if (copy == NULL) {
        return CF_ERR_MALLOC;
    }
    if (memcpy_s(copy, data->size, data->data, data->size) != EOK) {
        CfFree(copy);
        return CF_ERR_COPY;
    }
    if (entry->data != NULL) {
        CfFree(entry->data);
    }
    if (strncpy_s(entry->identifier, sizeof(entry->identifier), identifier, MAX_REVOCATION_CACHE_ID_LEN - 1) != EOK) {
        CfFree(copy);
        return CF_ERR_COPY;
    }
    entry->identifier[MAX_REVOCATION_CACHE_ID_LEN - 1] = '\0';
    entry->type = type;
    entry->data = copy;
    entry->size = data->size;
    entry->valid = true;
    return CF_SUCCESS;
}

CfResult __wrap_RevocationCacheStore(const char *identifier, HcfRevocationType type,
    const CfBlob *data, uint64_t expirationTime)
{
    (void)expirationTime;
    CfResult ret = StoreToMockCache(identifier, type, data);
    if (ret == CF_SUCCESS) {
        g_mockStoreCalled = true;
    }
    return ret;
}

CfResult __wrap_RevocationCacheQuery(const char *identifier, HcfRevocationType type, CfBlob *dataOut)
{
    if (identifier == NULL || dataOut == NULL) {
        return CF_ERR_PARAMETER_CHECK;
    }
    MockCacheEntry *entry = FindEntry(identifier, type);
    if (entry == NULL || !entry->valid || entry->data == NULL) {
        return CF_NOT_EXIST;
    }
    uint8_t *copy = (uint8_t *)CfMalloc(entry->size, 0);
    if (copy == NULL) {
        return CF_ERR_MALLOC;
    }
    if (memcpy_s(copy, entry->size, entry->data, entry->size) != EOK) {
        CfFree(copy);
        return CF_ERR_COPY;
    }
    dataOut->data = copy;
    dataOut->size = entry->size;
    g_mockQueryHit = true;
    return CF_SUCCESS;
}