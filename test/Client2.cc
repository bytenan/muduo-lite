/*长连接测试2：创建一个客户端向服务器一条发送数据，然后陷入循环，直到达到非活跃连接超时时间，看是否会断开连接*/

#include "../source/Server.hpp"

int main() {

    Socket client;
    client.CreateClient(8888, "127.0.0.1");
    std::string req = "Get /hello HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    assert(client.Send(req.c_str(), req.size()) != -1);
    char buf[1024] = { 0 };
    client.Recv(buf, sizeof(buf) - 1);
    DBG_LOG("[%s]", buf);
    while (true); 
    client.Close();
    
    return 0;
}