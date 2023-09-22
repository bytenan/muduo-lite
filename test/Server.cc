#include "../source/Server.hpp"

void Test1() {
    Socket server;
    server.CreateServer(8888);
    while (true) {
        int fd = server.Accept();
        if (fd < 0) {
            ERR_LOG("SERVER ACCEPT ERROR");
            continue;
        }
        Socket sockfd(fd);
        char buf[1024];
        int ret = sockfd.Recv(buf, sizeof(buf) - 1);
        if (ret < 0) {
            sockfd.Close();
            continue;
        }
        sockfd.Send(buf, ret);
        sockfd.Close();
    }
    server.Close();
}

void Close(Channel *channel) {
    std::cout << "close: " << channel->Fd() << std::endl;
    channel->RemoveMonitor();
    delete channel;
}
void Read(Channel *channnel) {
    char buf[1024];
    int n = read(channnel->Fd(), buf, sizeof(buf) - 1);
    if (n <= 0) {
        Close(channnel);
        return;
    }
    buf[n] = '\0';
    std::cout << buf << std::endl;
    channnel->EnableMonitorWriter();
}
void Write(Channel *channel) {
    std::string msg = "终于要成功了吗？";
    int n = write(channel->Fd(), msg.c_str(), msg.size());
    if (n < 0) {
        Close(channel);
        return;
    }
    channel->DisableMonitorWriter();
}
void Error(Channel *channel) {
    Close(channel);
}
void Any(Channel *channel) {
    std::cout << "有事件触发啦！！！" << std::endl;
}
void Acceptor(Epoller *epoller, int fd) {
    int newfd = accept(fd, nullptr, nullptr);
    if (newfd < 0) return;
    Channel *channel = new Channel(epoller, newfd);
    channel->SetReadCallBack(std::bind(Read, channel));
    channel->SetWriteCallBack(std::bind(Write, channel));
    channel->SetCloseCallBack(std::bind(Close, channel));
    channel->SetErrorCallBack(std::bind(Error, channel));
    channel->SetAnyCallBack(std::bind(Any, channel));
    channel->EnableMonitorRead();
}

void Test2() {

    Epoller epoller;

    Socket server;
    server.CreateServer(8888);

    Channel channel(&epoller, server.Fd());
    channel.SetReadCallBack(std::bind(Acceptor, &epoller, server.Fd()));
    channel.EnableMonitorRead();

    while(true) {
        std::vector<Channel *> actives;
        epoller.Epoll(&actives);
        for (auto &channel : actives) {
            channel->EventHandler();
        }
    }
    server.Close();
}


int main() {

    Test2();

    return 0;
}