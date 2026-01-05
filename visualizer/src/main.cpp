#include <curl/curl.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "model.hpp"
#include "parser.hpp"
#include "svg_graph.hpp"

static size_t append_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* s = static_cast<std::string*>(userdata);
    s->append(ptr, size * nmemb);
    return size * nmemb;
}

std::string http_post(const std::string& url, const std::string& data) {
    CURL* curl = curl_easy_init();
    std::string out;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data.size());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcprov_visualizer/1.0");
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return out;
}

int main() {
    uint64_t job_id = 1;
    std::string cluster_name = "cname1";
    std::string payload = R"({"job_id":)" + std::to_string(job_id)
                          + R"(,"cluster_name":")" + cluster_name + R"("})";
    std::string url = "http://127.0.0.1:9000/graph_api";
    std::string body = http_post(url, payload);
    // std::cout << "Parsed data: " << body << std::endl;
    ParsedLibcprovData parsed_libcprov_data = parse_injector_data(body);
    if (parsed_libcprov_data.response_type == ResponseType::ProvData) {
        build_graph(parsed_libcprov_data.job_data.value());
        std::cout << "Parsed data: " << body << std::endl;
    } else if (parsed_libcprov_data.response_type == ResponseType::Error) {
        std::cout << "Error" << std::endl;
    }
    return 0;
}
