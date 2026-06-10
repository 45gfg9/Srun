/* Copyright © 2023-2026 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <curl/curl.h>

typedef char *(*client_req_func)(CURL *);

struct curl_string {
  char *ptr;
  size_t len;
};

static void init_curl(void) __attribute__((constructor));
static void init_curl(void) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

static void cleanup_curl(void) __attribute__((destructor));
static void cleanup_curl(void) {
  curl_global_cleanup();
}

static void init_string(struct curl_string *s) {
  s->len = 0;
  s->ptr = calloc(1, 1); // initial null-terminated string
}

static size_t curl_ptr_writefunc(char *ptr, size_t size, size_t nmemb, void *userdata) {
  struct curl_string *s = userdata;
  size_t new_len = s->len + size * nmemb;
  char *new_ptr = realloc(s->ptr, new_len + 1);
  if (new_ptr == NULL) {
    return 0; // cause curl to fail
  }

  s->ptr = new_ptr;
  memcpy(s->ptr + s->len, ptr, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size * nmemb;
}

static size_t curl_null_writefunc(char *ptr, size_t size, size_t nmemb, void *userdata) {
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

static char *write_cert_to_tempfile(const char *cert_pem) {
  const char *tmpdir = getenv("TMPDIR");
  if (!tmpdir) {
    tmpdir = "/tmp";
  }

  char *template;
  if (asprintf(&template, "%s/certXXXXXX", tmpdir) == -1) {
    return NULL;
  }

  int fd = mkstemp(template);
  if (fd == -1) {
    free(template);
    return NULL;
  }

  ssize_t written = write(fd, cert_pem, strlen(cert_pem));
  close(fd);

  if (written != (ssize_t)strlen(cert_pem)) {
    unlink(template);
    free(template);
    return NULL;
  }

  return template; // Caller must unlink() and free()
}

static char *request(const_srun_handle handle, const char *url, client_req_func func) {
  CURL *curl_handle = curl_easy_init();
  if (!curl_handle) {
    // https://curl.se/libcurl/c/curl_easy_init.html
    // curl_easy_init is unlikely to fail
    errno = EAGAIN; // resource temporarily unavailable
    return NULL;
  }

  curl_easy_setopt(curl_handle, CURLOPT_URL, url);

  if (handle->if_name) {
    curl_easy_setopt(curl_handle, CURLOPT_INTERFACE, handle->if_name);
  }

  if (handle->verbosity >= SRUN_VERBOSITY_DEBUG) {
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  }

  char *cert_path = handle->cacert_path;
  int temp_file_used = 0;
  if (handle->cacert_pem) {
    temp_file_used = 1;
    cert_path = write_cert_to_tempfile(handle->cacert_pem);
    if (!cert_path) {
      curl_easy_cleanup(curl_handle);
      errno = EIO;
      return NULL;
    }
    srun_log_debug(handle->verbosity, "Certificate written to %s\n", cert_path);
  }
  if (cert_path) {
    curl_easy_setopt(curl_handle, CURLOPT_CAINFO, cert_path);
  }

  char *ret = func(curl_handle);

  curl_easy_cleanup(curl_handle);
  if (temp_file_used) {
    unlink(cert_path);
    free(cert_path);
  }

  return ret;
}

static char *request_get_body_func(CURL *curl_handle) {
  struct curl_string resp_string;
  init_string(&resp_string);

  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_ptr_writefunc);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &resp_string);

  CURLcode res = curl_easy_perform(curl_handle);
  if (res != CURLE_OK) {
    srun_log_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    free(resp_string.ptr);
    errno = EIO;
    return NULL;
  }

  return resp_string.ptr;
}

char *request_get_body(const_srun_handle handle, const char *url) {
  return request(handle, url, request_get_body_func);
}

static char *request_get_location_func(CURL *curl_handle) {
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_null_writefunc);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, NULL);

  CURLcode res = curl_easy_perform(curl_handle);
  if (res != CURLE_OK) {
    srun_log_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    errno = EIO;
    return NULL;
  }

  char *location = NULL;
  res = curl_easy_getinfo(curl_handle, CURLINFO_REDIRECT_URL, &location);
  if (res != CURLE_OK) {
    srun_log_error("curl_easy_getinfo() failed: %s\n", curl_easy_strerror(res));
    errno = EIO;
    return NULL;
  }

  if (location && location[0]) {
    return strdup(location);
  }
  return NULL;
}

char *request_get_location(const_srun_handle handle, const char *url) {
  return request(handle, url, request_get_location_func);
}
