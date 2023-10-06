/*给服务端传输一个大文件，看服务器能否正常接收*/

#include "../source/http/Http.hpp"

int main() {

    Socket client;
    client.CreateClient(8888, "127.0.0.1");
    std::string body;
    if(!Util::ReadFile("hello.txt", &body)) {
        DBG_LOG("READ FILE ERROR");
        return -1;
    }
    std::string head = "Put /1234.txt HTTP/1.1\r\nConnection: keep-alive\r\n";
    head += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
    assert(client.Send(head.c_str(), head.size()) != -1);
    assert(client.Send(body.c_str(), body.size()) != -1);
    char buf[1024] = { 0 };
    client.Recv(buf, sizeof(buf) - 1);
    DBG_LOG("[%s]", buf);
    client.Close();
    
    return 0;
}