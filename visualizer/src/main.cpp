#include <cstdlib>
#include <string>

int main() {
  std::string payload = "189524579029139492";
  std::string cmd =
      "curl -s -X POST -d '" + payload + "' http://127.0.0.1:9000/graph_api";
  int ret = std::system(cmd.c_str());
  return ret;
}
