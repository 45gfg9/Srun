/* Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#if ARDUINO && ESP8266

#include "compat.h"

#include <memory>
#include <WiFiClientSecure.h>
#include <ESP8266HTTPClient.h>

using client_req_func = char *(HTTPClient &client);

static char *request(const_srun_handle handle, const char *url, client_req_func func) {
  std::unique_ptr<WiFiClient> pclient;
  HTTPClient http;

  if (strncmp(url, "https://", 8) == 0) {
    auto psecure = new WiFiClientSecure;
    pclient.reset(psecure);

    // For ESP8266, we disable certificate verification completely because it
    // will always verify cert expiration time, however when not connected the
    // time cannot be synced.
    // By contrast ESP-IDF supports certificate verification w/o time check
    psecure->setInsecure();
  } else {
    pclient.reset(new WiFiClient);
  }
  http.begin(*pclient, url);

  char *response = func(http);

  http.end();
  return response;
}

char *request_get_body(const_srun_handle handle, const char *url) {
  return request(handle, url, [](HTTPClient &http) -> char * {
    int httpCode = http.GET();
    if (httpCode > 0) {
      String payload = http.getString();
      return strdup(payload.c_str());
    }
    return nullptr;
  });
}

char *request_get_location(const_srun_handle handle, const char *url) {
  return request(handle, url, [](HTTPClient &http) -> char * {
    int httpCode = http.GET();
    if (httpCode >= 300 && httpCode < 400) {
      String location = http.getLocation();
      if (!location.isEmpty()) {
        return strdup(location.c_str());
      }
    }
    return nullptr;
  });
}

#endif
