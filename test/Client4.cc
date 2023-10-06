/*一次性给服务器发送多条请求，看服务器能否正常处理每个请求*/

#include "../source/Server.hpp"

int main() {

    Socket client;
    client.CreateClient(8888, "127.0.0.1");
    std::string req = "Get /hello HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    req += "Get /hello HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"; 
    req += "Get /hello HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"; 
    while (true) {
        assert(client.Send(req.c_str(), req.size()) != -1);
        char buf[1024] = { 0 };
        client.Recv(buf, sizeof(buf) - 1);
        DBG_LOG("[%s]", buf);
        sleep(5);
    }
    client.Close();
    
    return 0;
}