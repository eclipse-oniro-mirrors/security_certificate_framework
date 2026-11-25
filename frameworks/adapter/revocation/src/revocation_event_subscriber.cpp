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

#include "revocation_event_subscriber.h"

#include <memory>
#include <mutex>

#include "cf_log.h"
#include "revocation_check.h"

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace EventFwk {

/* Action published by cert manager when CA cert is enabled/disabled or the
 * revocation force-check policy is updated */
static constexpr const char *CM_EVENT_ACTION_CA_STATUS =
    "certmanager.event.CA_CERT_STATUS_CHANGED";
/* Parameters/values carried by the event; "type" selects which revocation
 * policy cache the update applies to. Mirrors cm_cert_status_event.h. */
static constexpr const char *CM_EVENT_PARAM_TYPE = "type";
static constexpr const char *CM_EVENT_TYPE_SYSTEM_CA = "SYSTEM_CA";
static constexpr const char *CM_EVENT_TYPE_REVOCATION_FORCE_CHECK = "REVOCATION_FORCE_CHECK";

class RevocationEventSubscriber : public CommonEventSubscriber {
public:
    explicit RevocationEventSubscriber(const CommonEventSubscribeInfo &info)
        : CommonEventSubscriber(info) {}

    void OnReceiveEvent(const CommonEventData &data) override
    {
        const auto &want = data.GetWant();
        std::string action = want.GetAction();
        if (action != CM_EVENT_ACTION_CA_STATUS) {
            return;
        }
        std::string type = want.GetStringParam(CM_EVENT_PARAM_TYPE);
        if (type == CM_EVENT_TYPE_SYSTEM_CA) {
            LOGI("revocation: SYSTEM_CA status changed, clearing user cache");
            RevocationNotifyUserCfgUpdate();
        } else if (type == CM_EVENT_TYPE_REVOCATION_FORCE_CHECK) {
            LOGI("revocation: force-check policy updated, clearing cloud cache");
            RevocationNotifyCloudCfgUpdate();
        } else {
            LOGW("revocation: unknown CA status event type [%s], ignore", type.c_str());
        }
    }
};

} // namespace EventFwk
} // namespace OHOS

static std::shared_ptr<OHOS::EventFwk::RevocationEventSubscriber> g_subscriber = nullptr;
static std::mutex g_subscriberMutex;

extern "C" int32_t RevocationEventSubscribe(void)
{
    std::lock_guard<std::mutex> lock(g_subscriberMutex);
    if (g_subscriber != nullptr) {
        LOGI("revocation: event subscriber already active");
        return 0;
    }
    OHOS::EventFwk::MatchingSkills skills;
    skills.AddEvent(OHOS::EventFwk::CM_EVENT_ACTION_CA_STATUS);
    OHOS::EventFwk::CommonEventSubscribeInfo info(skills);
    g_subscriber = std::make_shared<OHOS::EventFwk::RevocationEventSubscriber>(info);
    bool ok = OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(g_subscriber);
    if (!ok) {
        LOGE("revocation: subscribe common event failed");
        g_subscriber = nullptr;
        return -1;
    }
    LOGI("revocation: subscribed to CA cert status change events");
    return 0;
}

extern "C" void RevocationEventUnsubscribe(void)
{
    std::lock_guard<std::mutex> lock(g_subscriberMutex);
    if (g_subscriber == nullptr) {
        return;
    }
    bool ok = OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(g_subscriber);
    if (!ok) {
        LOGE("revocation: unsubscribe common event failed");
    } else {
        LOGI("revocation: unsubscribed from CA cert status change events");
    }
    g_subscriber = nullptr;
}
