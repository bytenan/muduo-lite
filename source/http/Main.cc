#include "Http.hpp"

int main() {

    //std::string str = ",,abc,,,def,,gh,,,";
    //std::string sep = ",";
    //std::vector<std::string> array;
    //int n = Util::Split(str, sep, &array);
    //for (auto &s : array) {
    //    std::cout << s << std::endl;
    //}

    //std::string filename = "./Http.hpp";
    //std::string str;
    //if (Util::ReadFile(filename, &str)) {
    //    std::cout << str << std::endl;
    //}

    //std::string filename1 = "./ttt.cc";
    //Util::WriteFile(filename1, str);

    //std::string str = "c  ";
    //std::string ans1 = Util::UrlEncode(str, true);
    //std::string ans2 = Util::UrlDecode(ans1, true);
    //std::cout << ans1 << std::endl;
    //std::cout << ans2 << "c" << std::endl;

    //std::cout << Util::StatuDescription(200) << std::endl;
    //std::cout << Util::StatuDescription(800) << std::endl;

    //std::cout << Util::ExtendMime("a.txt") << std::endl;
    //std::cout << Util::ExtendMime("a.png") << std::endl;
    //std::cout << Util::ExtendMime("a.xxxxx") << std::endl;

    //std::cout << Util::IsDirectoryFile("../http") << std::endl;
    //std::cout << Util::IsDirectoryFile("test.cc") << std::endl;
    //std::cout << Util::IsRegularFile("../http") << std::endl;
    //std::cout << Util::IsRegularFile("test.cc") << std::endl;

    std::cout << Util::IsValidPath("/html/../../index.html") << std::endl;

    return 0;
}