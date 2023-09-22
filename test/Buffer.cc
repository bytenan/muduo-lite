#include "../source/Server.hpp"

int main() {

   // Buffer buf;
   // std::string str = "hello world";
   // buf.WriteStringAndPushOffSet(str);
   // std::string ans = buf.ReadAsStringAndPushOffSet(buf.ReadableSize());
   // std::cout << ans << std::endl;
   // std::cout << buf.ReadableSize() << std::endl;
    Buffer buf;
    for (int i = 0; i < 500; ++i) {
        std::string str = "hello world" + std::to_string(i) + "\n";
        buf.WriteStringAndPushOffSet(str);
    }
    while (buf.ReadableSize() > 0) {
        std::string line = buf.GetLineAndPushOffSet();
        std::cout << line;
    }
    std::cout << buf.ReadableSize() << std::endl;

    return 0;
}