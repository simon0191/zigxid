#include <iostream>
#include <sys/sysctl.h>

namespace simon {
  std::string machine_id() {
    std::size_t size = 40;
    char buffer[40];

    sysctlbyname("kern.uuid", &buffer, &size, nullptr, 0);

    return buffer;
  }
}

// int main() {
//   std::cout << simon::machine_id() << std::endl;
//   return 0;
// }
