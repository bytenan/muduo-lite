#include "../source/Server.hpp"

std::unordered_map<int, ConnectionSharedPtr> conns;
int id = rand() % 10000;
std::vector<Loopthread> threads(2);
int next_loop = 0;
LoopThreadPool *loop_pool;

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

void NewConnection(int fd) {
    ++id;
    ConnectionSharedPtr conn(new Connection(loop_pool->Loop(), id, fd));
    conn->SetMessageCallBack(std::bind(OnMessage, std::placeholders::_1, std::placeholders::_2));
    conn->SetConnectCallBack(std::bind(OnConnect, std::placeholders::_1));
    conn->SetServerCloseCallBack(std::bind(ConnectionDestroy, std::placeholders::_1));
    conn->EnableInactiveRelease(10);
    conn->Established();
    conns[id] = conn;
    DBG_LOG("NEW CONNECTION");
}

int main() {
    srand(time(nullptr));

    EventLoop base_loop;
    loop_pool = new LoopThreadPool(&base_loop);
    loop_pool->SetThreadLoopSize(2);
    loop_pool->Create();

    Acceptor acceptor(&base_loop, 8888);
    acceptor.SetReadCallBack(std::bind(NewConnection, std::placeholders::_1));
    acceptor.Listen();

    base_loop.Run();

    return 0;
}