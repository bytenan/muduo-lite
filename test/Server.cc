#include "../source/Server.hpp"

std::unordered_map<int, ConnectionSharedPtr> conns;
int id = rand() % 10000;

void OnMessage(const ConnectionSharedPtr &conn, Buffer *buf) {
    DBG_LOG("%s", buf->ReaderPosition());
    buf->MoveReaderOffset(buf->ReadableSize());
    std::string msg = "终于要胜利了！！！";
    conn->Send(msg.c_str(), msg.size());
}

void OnConnect(const ConnectionSharedPtr &conn) {
    DBG_LOG("NEW CONNECTION: %p", conn.get());
}

void ConnectionDestroy(const ConnectionSharedPtr &conn) {
    conns.erase(conn->Id());
}

void Acceptor(EventLoop *loop, int fd) {
    int newfd = accept(fd, nullptr, nullptr);
    if (newfd < 0) return;
    ++id;
    ConnectionSharedPtr conn(new Connection(loop, id, newfd));
    conn->SetMessageCallBack(std::bind(OnMessage, std::placeholders::_1, std::placeholders::_2));
    conn->SetConnectCallBack(std::bind(OnConnect, std::placeholders::_1));
    conn->SetServerCloseCallBack(std::bind(ConnectionDestroy, std::placeholders::_1));
    conn->EnableInactiveRelease(10);
    conn->Established();
    conns[id] = conn;
}

int main() {
    srand(time(nullptr));

    EventLoop loop;

    Socket server;
    server.CreateServer(8888);

    Channel channel(&loop, server.Fd());
    channel.SetReadCallBack(std::bind(Acceptor, &loop, server.Fd()));
    channel.EnableMonitorRead();

    while(true) {
        loop.Run();
    }
    server.Close();

    return 0;
}