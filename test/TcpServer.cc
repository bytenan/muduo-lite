#include "../source/Server.hpp"

void OnMessage(const ConnectionSharedPtr &conn, Buffer *buf) {
    DBG_LOG("%s", buf->ReaderPosition());
    buf->MoveReaderOffset(buf->ReadableSize());
    std::string msg = "终于要胜利了！！！";
    conn->Send(msg.c_str(), msg.size());
}

void OnConnect(const ConnectionSharedPtr &conn) {
    DBG_LOG("A new connection: %p", conn.get());
}

void OnClose(const ConnectionSharedPtr &conn) {
    DBG_LOG("Close a Connection: %p", conn.get());
}

void OnAny(const ConnectionSharedPtr &conn) {
    DBG_LOG("A Any Event: %p", conn.get());
}

int main() {

    TcpServer server(8888);
    //server.SetThreadLoopSize(2);
    server.EnableInactiveRelease(10);
    server.SetConnectCallBack(OnConnect);
    server.SetMessageCallBack(OnMessage);
    server.SetCloseCallBack(OnClose);
    //server.SetAnyCallBack(OnAny);
    server.Run();

    return 0;
}