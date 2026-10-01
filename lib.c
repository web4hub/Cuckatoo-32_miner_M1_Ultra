#include <curl/curl.h>

int main(void) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *curl = curl_easy_init();
  if (!curl) {
    curl_global_cleanup();
    return 1;
  }

  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
  curl_easy_setopt(curl, CURLOPT_URL, "https://grin.2miners.com/api/accounts/%7Bwalletid%7D");

  CURLcode res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
