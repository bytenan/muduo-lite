#include "../Server.hpp"

class EchoServer {
public:
    EchoServer(int port) : server_(port) {
        server_.SetThreadLoopSize(2);
        server_.EnableInactiveRelease(10);
        server_.SetConnectCallBack(std::bind(&EchoServer::OnConnect, this, std::placeholders::_1));
        server_.SetMessageCallBack(std::bind(&EchoServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
        server_.SetCloseCallBack(std::bind(&EchoServer::OnClose, this, std::placeholders::_1));
        // server_.SetAnyCallBack(std::bind(EchoServer::OnAny, this, std::placeholders::_1));
    }
    void Start() {
        server_.Run();
    }
private:
    void OnMessage(const ConnectionPtr &conn, Buffer *buf) {
        conn->Send(buf->ReaderPosition(), buf->ReadableSize());
        buf->MoveReaderOffset(buf->ReadableSize());
        conn->Shutdown(); 
    }
    void OnConnect(const ConnectionPtr &conn) {
        DBG_LOG("A new connection: %p", conn.get());
    }
    void OnClose(const ConnectionPtr &conn) {
        DBG_LOG("Close a Connection: %p", conn.get());
    }
    void OnAny(const ConnectionPtr &conn) {
        DBG_LOG("A Any Event: %p", conn.get());
    }

private:
    TcpServer server_;
};