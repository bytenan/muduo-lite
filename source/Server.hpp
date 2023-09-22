#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <functional>
#include <thread>
#include <mutex>
#include <cstdio>
#include <ctime>
#include <cassert>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#define INF 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL INF

#define LOG(level, format, ...) do {                                                          \
    if (level < LOG_LEVEL) break;                                                             \
    time_t t = time(nullptr);                                                                 \
    struct tm *lt = localtime(&t);                                                            \
    char time_tmp[64] = { 0 };                                                                \
    strftime(time_tmp, sizeof(time_tmp) - 1, "%Y-%m-%d %H:%M:%S", lt);                        \
    fprintf(stdout, "[%s] %s:%d: " format "\n", time_tmp, __FILE__, __LINE__, ##__VA_ARGS__); \
} while (0)

#define INF_LOG(format, ...) LOG(INF, format, ##__VA_ARGS__);
#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__);
#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__);

#define BUFFER_DEFAULT_SIZE 1024
class Buffer {
public:
    Buffer() : buffer_(BUFFER_DEFAULT_SIZE), reader_offset_(0), writer_offset_(0) {}
    // 获取读位置
    char *ReaderPosition() { return &(*buffer_.begin()) + reader_offset_; }
    // 获取写位置
    char *WriterPosition() { return &(*buffer_.begin()) + writer_offset_; }
    // 获取可读大小
    uint64_t ReadableSize() { return writer_offset_ - reader_offset_; }
    // 获取头部可写大小（reader之前）
    uint64_t HeadWritableSize() { return reader_offset_; }
    // 获取尾部可写大小（writer之后）
    uint64_t TailWritableSize() { return buffer_.size() - writer_offset_; }
    // 向后移动读偏移量
    void MoveReaderOffset(uint64_t len) {
        if (len == 0) return;
        assert(len <= ReadableSize());
        reader_offset_ += len;
    }
    // 向后移动写偏移量
    void MoveWriterOffset(uint64_t len) {
        if (len == 0) return;
        assert(len <= TailWritableSize());
        writer_offset_ += len;
    }  
    // 确保可写空间大小足够
    void EnsureWritableSpaceEnough(uint64_t len) {
        if (len == 0) return;
        if (len <= TailWritableSize()) {
            // 若尾部空间大小足够，则直接返回
            return;
        } else if (len <= HeadWritableSize() + TailWritableSize()) {
            // 若尾部空间大小不够，但加上头部空间大小就足够了，那么就将数据全部移动到头部
            std::copy(ReaderPosition(), ReaderPosition() + ReadableSize(), buffer_.begin());
            reader_offset_ = 0;
            writer_offset_ = ReadableSize();
        } else {
            // 若尾部空间和头部空间加起来都不够，直接在尾部扩容
            buffer_.resize(writer_offset_ + len);
        }
    }
    // 向Buffer实例中写入数据
    void Write(const void *data, uint64_t len) {
        if (len == 0) return;
        EnsureWritableSpaceEnough(len);
        // 由于void*没有步长，所以这里强转成char*
        std::copy((const char *)data, (const char *)data + len, WriterPosition());
    }
    // 向Buffer实例中写入数据，并且移动写偏移
    void WriteAndPushOffSet(const void *data, uint64_t len) {
        if (len == 0) return;
        Write(data, len);
        MoveWriterOffset(len);
    }
    // 向Buffer实例中写入一个string实例
    void WriteString(const std::string &str) {
        if (str.size() == 0) return;
        Write(str.c_str(), str.size());
    }
    // 向Buffer实例中写入一个string实例，并且移动写偏移
    void WriteStringAndPushOffSet(const std::string &str) {
        if (str.size() == 0) return;
        WriteString(str);
        MoveWriterOffset(str.size());
    }
    // 向Buffer实例中写入一个Buffer实例
    void WriteBuffer(Buffer &buf) {
        if (buf.ReadableSize() == 0) return;
        Write(buf.ReaderPosition(), buf.ReadableSize());
    }
    // 向Buffer实例中写入一个Buffer实例，并且移动写偏移
    void WriteBufferAndPushOffSet(Buffer &buf) {
        if (buf.ReadableSize() == 0) return;
        WriteBuffer(buf);
        MoveWriterOffset(buf.ReadableSize());
    }
    // 从Buffer实例中读出数据
    void Read(void *buf, uint64_t len) {
        if (len == 0) return;
        assert(len <= ReadableSize());
        std::copy(ReaderPosition(), ReaderPosition() + len, (char *)buf);
    }
    // 从Buffer实例中读出数据，并且移动读偏移
    void ReadAndPushOffSet(void *buf, uint64_t len) {
        if (len == 0) return;
        Read(buf, len);
        MoveReaderOffset(len);
    }
    // 从Buffer实例中读出一个string实例
    std::string ReadAsString(uint64_t len) {
        if (len == 0) return "";
        assert(len <= ReadableSize());
        std::string str;
        str.resize(len);
        Read(&str[0], len);
        return str; 
    }
    // 从Buffer实例中读出一个string实例，并且移动读偏移
    std::string ReadAsStringAndPushOffSet(uint64_t len) {
        if (len == 0) return "";
        assert(len <= ReadableSize());
        std::string str = ReadAsString(len);
        MoveReaderOffset(len);
        return str;
    }
    // 从Buffer实例中读出一行数据（以'\n'结尾，数据中包含'\n'）
    std::string GetLine() {
        char *pos = (char *)memchr(ReaderPosition(), '\n', ReadableSize());
        if (pos == nullptr) return "";
        return ReadAsString(pos - ReaderPosition() + 1);
    }
    // 从Buffer实例中读出一行数据（以'\n'结尾，数据中包含'\n'），并且移动读偏移
    std::string GetLineAndPushOffSet() {
        std::string str = GetLine();
        MoveReaderOffset(str.size());
        return str;
    }
    // 清空Buffer实例
    void Clear() { reader_offset_ = writer_offset_ = 0; }
    
private:
    std::vector<char> buffer_; // 缓冲区
    size_t reader_offset_; // 读偏移
    size_t writer_offset_; // 写偏移
};

#define DEFAULT_BACKLOG 1024
class Socket {
public:
    Socket() : fd_(-1) {}
    Socket(int fd) : fd_(fd) {}
    int Fd() { return fd_; }
    bool Create() {
        fd_  = socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) {
            ERR_LOG("SOCKET CREATE ERROR");
            return false;
        }
        return true;
    }
    bool Bind(const std::string &ip, uint16_t port) {
        struct sockaddr_in local;
        local.sin_family = AF_INET;        
        local.sin_addr.s_addr = inet_addr(ip.c_str());
        local.sin_port = htons(port);
        int ret = bind(fd_, (struct sockaddr *)&local, sizeof(local));
        if (ret < 0) {
            ERR_LOG("SOCKET BIND ERROR");
            return false;
        }
        return true;
    }
    bool Listen(int backlog = DEFAULT_BACKLOG) {
        int ret = listen(fd_, backlog);
        if (ret < 0) {
            ERR_LOG("SOCKET LISTEN ERROR");
            return false;
        }
        return true;
    }
    bool Connect(const std::string &ip, uint16_t port) {
        struct sockaddr_in peer;
        peer.sin_family = AF_INET;        
        peer.sin_addr.s_addr = inet_addr(ip.c_str());
        peer.sin_port = htons(port);
        int ret = connect(fd_, (struct sockaddr *)&peer, sizeof(peer));
        if (ret < 0) {
            ERR_LOG("SOCKET CONNET ERROR");
            return false;
        }
        return true;
    }
    int Accept() {
        int fd = accept(fd_, nullptr, nullptr);
        if (fd < 0) {
            ERR_LOG("SOCKET ACCEPT ERROR");
            return -1;
        } 
        return fd;
    }
    // 默认阻塞读取
    ssize_t Recv(void *buf, size_t len, int flag = 0) {
        int n = recv(fd_, buf, len, flag);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EINTR) {
                return 0;
            }
            ERR_LOG("SOCKET RECV ERROR");
            return -1;
        }
        return n;
    }
    // 非阻塞读取
    ssize_t RecvNonBlock(void *buf, size_t len) {
        return Recv(buf, len, MSG_DONTWAIT);
    }
    // 默认阻塞发送
    ssize_t Send(const void *buf, size_t len, int flag = 0) {
        int n = send(fd_, buf, len, flag);
        if (n < 0) {
            ERR_LOG("SOCKET SEND ERROR");
            return -1;
        } 
        return n;
    }
    // 非阻塞发送
    ssize_t SendNonBlock(const void *buf, size_t len) {
        return Send(buf, len, MSG_DONTWAIT);
    }
    void Close() {
        if (fd_ != -1) {
            close(fd_);
            fd_ = -1;
        }
    }
    bool CreateServer(uint16_t port, const std::string &ip = "0.0.0.0", bool flag = false) {
        if (!Create()) return false;
        if (flag && !SetNonBlock()) return false;
        if (!Bind(ip, port)) return false;
        if (!Listen()) return false;
        if (!SetAddressReuse()) return false;
        return true;
    }
    bool CreateClient(uint16_t port, const std::string &ip) {
        if (!Create()) return false;
        if (!Connect(ip, port)) return false;
        return true;
    }
    // 设置fd_地址重用
    bool SetAddressReuse() {
        int opt = 1;
        int ret = setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof opt);
        if (ret < 0) return false;
        return true;
    }
    // 设置fd_非阻塞
    bool SetNonBlock() {
        int flag = fcntl(fd_, F_GETFL, 0);
        if (flag < 0) return false;
        if (fcntl(fd_, F_SETFL, flag |= O_NONBLOCK) < 0) return false;
        return true;
    }
private:
    int fd_;
};

class Epoller; 
// 文件描述符的事件管理
using EventCallBack = std::function<void()>;
class Channel {
public:
    Channel(Epoller *epoller, int fd) : epoller_(epoller), fd_(fd), events_(0), revents_(0) {}
    int Fd() { return fd_; }
    // 获取要监控的事件
    uint32_t Events() { return events_; }
    // 将已经触发的事件设置进来
    void SetREvents(uint32_t revents) { revents_ = revents; }
    // 设置读事件回调
    void SetReadCallBack(const EventCallBack &read_callback) { 
        read_callback_ = read_callback;
    }
    // 设置写事件回调
    void SetWriteCallBack(const EventCallBack &write_callback) {
        write_callback_ = write_callback;
    }
    // 设置错误事件回调
    void SetErrorCallBack(const EventCallBack &error_callback) {
        error_callback_ = error_callback;
    }
    // 设置关闭事件回调
    void SetCloseCallBack(const EventCallBack &close_callback) {
        close_callback_ = close_callback;
    }
    // 设置任意事件回调
    void SetAnyCallBack(const EventCallBack &any_callback) {
        any_callback_ = any_callback;
    }
    // 判断读事件是否被监控
    bool IsMonitorRead() {
        return events_ & EPOLLIN;
    }
    // 判断写事件是否被监控
    bool IsMonitorWriter() {
        return events_ & EPOLLOUT;
    }
    // 开启读事件监控
    void EnableMonitorRead() {
        events_ |= EPOLLIN;
        UpdateMonitor();
    }
    // 开启写事件监控
    void EnableMonitorWriter() {
        events_ |= EPOLLOUT;
        UpdateMonitor();
    }
    // 关闭读事件监控
    void DisableMonitorRead() {
        events_ &= ~EPOLLIN;
        UpdateMonitor();
    }
    // 关闭写事件监控
    void DisableMonitorWriter() {
        events_ &= ~EPOLLOUT;
        UpdateMonitor();
    }
    // 关闭所有的事件监控
    void DisableMonitor() {
        events_ = 0;
        UpdateMonitor();
    }
    void UpdateMonitor();
    void RemoveMonitor(); 
    // 事件的处理函数（一旦有事件触发，就调用该函数，该函数内部会调用相应的事件触发回调函数）
    void EventHandler() {
        if ((revents_ & EPOLLIN) || (revents_ & EPOLLRDHUP) || (revents_ & EPOLLPRI)) {
            if (any_callback_) any_callback_();
            if (read_callback_) read_callback_();
        }        
        if (revents_ & EPOLLOUT) {
            if (any_callback_) any_callback_();
            if (write_callback_) write_callback_();
        } else if (revents_ & EPOLLERR) {
            if (any_callback_) any_callback_();
            if (error_callback_) error_callback_();
        } else if (revents_ & EPOLLHUP) {
            if (any_callback_) any_callback_();
            if (close_callback_) close_callback_();
        }
    }

private:
    Epoller *epoller_; 
    int fd_;
    uint32_t events_;  // 要监控的事件
    uint32_t revents_; // 已经触发的事件
    EventCallBack read_callback_;  // 读事件回调函数
    EventCallBack write_callback_; // 写事件回调函数
    EventCallBack error_callback_; // 错误事件回调函数
    EventCallBack close_callback_; // 关闭事件回调函数
    EventCallBack any_callback_;   // 任意事件回调函数
};

// 文件描述符的监控管理
#define EPOLLEVENTS_NUMS 1024
class Epoller {
public:
    Epoller() : epfd_(-1) {
        epfd_ = epoll_create(EPOLLEVENTS_NUMS);
        if (epfd_ < 0) {
            ERR_LOG("EPOLL CREATE ERROR");
            abort();
        }
    }
    ~Epoller() {
        if (epfd_ != -1) {
            close(epfd_);
            epfd_ = -1;
        }
    }
    // 更新事件监控
    void UpdateEventMonitor(Channel *channel) {
        if (HasChannel(channel)) {
            // channel已存在，更新事件监控
            Update(channel, EPOLL_CTL_MOD);
        } else {
            // channel不存在，添加事件监控
            channels_[channel->Fd()] = channel;
            Update(channel, EPOLL_CTL_ADD);
        }
    }
    // 移除事件监控
    void RemoveEventMonitor(Channel *channel) {
        if (HasChannel(channel)) {
            channels_.erase(channel->Fd());
        }
        Update(channel, EPOLL_CTL_DEL);
    }
    void Epoll(std::vector<Channel *> *active) {
        int nfds = epoll_wait(epfd_, events_, EPOLLEVENTS_NUMS, -1);
        if (nfds < 0) {
            if (errno == EINTR) return;
            ERR_LOG("EPOLL WAIT ERROR: %s", strerror(errno));
            abort();
        }
        for (int i = 0; i < nfds; ++i) {
            auto it = channels_.find(events_[i].data.fd);
            assert(it != channels_.end());
            it->second->SetREvents(events_[i].events);
            active->push_back(it->second);
        }
    }
private:
    // 实际执行epoll_ctl的函数
    void Update(Channel *channel, int op) {
        struct epoll_event event;
        event.data.fd = channel->Fd();
        event.events = channel->Events();
        int ret = epoll_ctl(epfd_, op, channel->Fd(), &event);
        if (ret < 0) {
            ERR_LOG("EPOLL CTL ERROR");
        }
    }
    bool HasChannel(Channel *channel) {
        auto it = channels_.find(channel->Fd());
        if (it == channels_.end()) return false;
        return true;
    }
private:
    int epfd_;
    struct epoll_event events_[EPOLLEVENTS_NUMS];
    std::unordered_map<int, Channel *> channels_;    
};

void Channel::UpdateMonitor() {
    epoller_->UpdateEventMonitor(this);
}
void Channel::RemoveMonitor() {
    epoller_->RemoveEventMonitor(this);
} 

using Functor = std::function<void()>;
class EventLoop {
public:
    EventLoop();
    void RunInLoop(const Functor &task);
    void QueueInLoop(const Functor &task);
    bool IsInLoop();
    void UpdateEventMonitor(Channel *channel);
    void RemoveEventMonitor(Channel *channel);
private:
    void RunAllTask();
private:
    std::thread::id thread_id_;    
    int eventfd_;
    Epoller epoller_;
    std::vector<Functor> tasks_;
    std::mutex mutex_;    
};