/*错误请求测试：客户端向服务器每次发送请求时，告诉服务器一个假的正文大小，而实际的正文大小是小于这个值的，看服务器如何处理
 *       1、只发送一次，服务器由于得不到完整的正文大小而不会进行业务处理，超时时间到了之后，连接断开
 *       2、发送多次，服务器就会将后面的请求当作前面请求的正文，此时处理时，就会当作错误请求处理
*/

#include "../source/Server.hpp"

int main() {

    Socket client;
    client.CreateClient(8888, "127.0.0.1");
    std::string req = "Get /hello HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 100\r\n\r\nwynzdnb";
    assert(client.Send(req.c_str(), req.size()) != -1);
    assert(client.Send(req.c_str(), req.size()) != -1);
    assert(client.Send(req.c_str(), req.size()) != -1);
    char buf[1024] = { 0 };
    client.Recv(buf, sizeof(buf) - 1);
    DBG_LOG("[%s]", buf);
    while (true);
    client.Close();
    
    return 0;
}