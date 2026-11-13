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

/* Action published by cert manager when CA cert is enabled/disabled */
static constexpr const char *CM_EVENT_ACTION_CA_STATUS =
    "certmanager.event.CA_CERT_STATUS_CHANGED";

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
        LOGI("revocation: received CA cert status change event, clearing user cache");
        RevocationNotifyUserCfgUpdate();
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
