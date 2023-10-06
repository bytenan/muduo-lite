#ifndef __SERVER_HPP__
#define __SERVER_HPP__

#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <functional>
#include <typeinfo>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <ctime>
#include <cstdio>
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

pid_t gettid() {
    return (pid_t)syscall(__NR_gettid);
}

#define INF 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL INF

#define LOG(level, format, ...) do {                                                                       \
    if (level < LOG_LEVEL) {                                                                               \
        break;                                                                                             \
    }                                                                                                      \
    time_t t = time(nullptr);                                                                              \
    struct tm *lt = localtime(&t);                                                                         \
    char time_tmp[64] = { 0 };                                                                             \
    strftime(time_tmp, sizeof(time_tmp) - 1, "%Y-%m-%d %H:%M:%S", lt);                                     \
    fprintf(stdout, "%d [%s] %s:%d: " format "\n", gettid(), time_tmp, __FILE__, __LINE__, ##__VA_ARGS__); \
} while (0)

#define INF_LOG(format, ...) LOG(INF, format, ##__VA_ARGS__);
#define DBG_LOG(format, ...) LOG(DBG, format, ##__VA_ARGS__);
#define ERR_LOG(format, ...) LOG(ERR, format, ##__VA_ARGS__);

#define BUFFER_DEFAULT_SIZE 1024
class Buffer {
public:
    Buffer() : buffer_(BUFFER_DEFAULT_SIZE), reader_offset_(0), writer_offset_(0) {}
    // 获取读位置
    char *ReaderPosition() {
        return &(*buffer_.begin()) + reader_offset_;
    }
    // 获取写位置
    char *WriterPosition() {
        return &(*buffer_.begin()) + writer_offset_;
    }
    // 获取可读大小
    uint64_t ReadableSize() {
        return writer_offset_ - reader_offset_;
    }
    // 获取头部可写大小（reader之前）
    uint64_t HeadWritableSize() {
        return reader_offset_;
    }
    // 获取尾部可写大小（writer之后）
    uint64_t TailWritableSize() {
        return buffer_.size() - writer_offset_;
    }
    // 向后移动读偏移量
    void MoveReaderOffset(uint64_t len) {
        if (len == 0) {
            return;
        }
        assert(len <= ReadableSize());
        reader_offset_ += len;
    }
    // 向后移动写偏移量
    void MoveWriterOffset(uint64_t len) {
        if (len == 0) {
            return;
        }
        assert(len <= TailWritableSize());
        writer_offset_ += len;
    }  
    // 确保可写空间大小足够
    void EnsureWritableSpaceEnough(uint64_t len) {
        if (len == 0) {
            return;
        }
        if (len <= TailWritableSize()) {
            // 若尾部空间大小足够，则直接返回
            return;
        } else if (len <= HeadWritableSize() + TailWritableSize()) {
            // 若尾部空间大小不够，但加上头部空间大小就足够了，那么就将数据全部移动到头部
            std::copy(ReaderPosition(), ReaderPosition() + ReadableSize(), &(*buffer_.begin()));
            reader_offset_ = 0;
            writer_offset_ = ReadableSize();
        } else {
            // 若尾部空间和头部空间加起来都不够，直接在尾部扩容
            buffer_.resize(writer_offset_ + len);
        }
    }
    // 向Buffer实例中写入数据
    void Write(const void *data, uint64_t len) {
        if (len == 0) {
            return;
        }
        EnsureWritableSpaceEnough(len);
        // 由于void*没有步长，所以这里强转成char*
        std::copy((const char *)data, (const char *)data + len, WriterPosition());
    }
    // 向Buffer实例中写入数据，并且移动写偏移
    void WriteAndPushOffSet(const void *data, uint64_t len) {
        if (len == 0) {
            return;
        }
        Write(data, len);
        MoveWriterOffset(len);
    }
    // 向Buffer实例中写入一个string实例
    void WriteString(const std::string &str) {
        if (str.size() == 0) {
            return;
        }
        Write(str.c_str(), str.size());
    }
    // 向Buffer实例中写入一个string实例，并且移动写偏移
    void WriteStringAndPushOffSet(const std::string &str) {
        if (str.size() == 0) {
            return;
        }
        WriteString(str);
        MoveWriterOffset(str.size());
    }
    // 向Buffer实例中写入一个Buffer实例
    void WriteBuffer(Buffer &buf) {
        if (buf.ReadableSize() == 0) {
            return;
        }
        Write(buf.ReaderPosition(), buf.ReadableSize());
    }
    // 向Buffer实例中写入一个Buffer实例，并且移动写偏移
    void WriteBufferAndPushOffSet(Buffer &buf) {
        if (buf.ReadableSize() == 0) {
            return;
        }
        WriteBuffer(buf);
        MoveWriterOffset(buf.ReadableSize());
    }
    // 从Buffer实例中读出数据
    void Read(void *buf, uint64_t len) {
        if (len == 0) {
            return;
        }
        assert(len <= ReadableSize());
        std::copy(ReaderPosition(), ReaderPosition() + len, (char *)buf);
    }
    // 从Buffer实例中读出数据，并且移动读偏移
    void ReadAndPushOffSet(void *buf, uint64_t len) {
        if (len == 0) {
            return;
        }
        Read(buf, len);
        MoveReaderOffset(len);
    }
    // 从Buffer实例中读出一个string实例
    std::string ReadAsString(uint64_t len) {
        if (len == 0) {
            return "";
        }
        assert(len <= ReadableSize());
        std::string str;
        str.resize(len);
        Read(&str[0], len);
        return str; 
    }
    // 从Buffer实例中读出一个string实例，并且移动读偏移
    std::string ReadAsStringAndPushOffSet(uint64_t len) {
        if (len == 0) {
            return "";
        }
        assert(len <= ReadableSize());
        std::string str = ReadAsString(len);
        MoveReaderOffset(len);
        return str;
    }
    // 从Buffer实例中读出一行数据（以'\n'结尾，数据中包含'\n'）
    std::string GetLine() {
        char *pos = (char *)memchr(ReaderPosition(), '\n', ReadableSize());
        if (pos == nullptr) {
            return "";
        }
        return ReadAsString(pos - ReaderPosition() + 1);
    }
    // 从Buffer实例中读出一行数据（以'\n'结尾，数据中包含'\n'），并且移动读偏移
    std::string GetLineAndPushOffSet() {
        std::string str = GetLine();
        MoveReaderOffset(str.size());
        return str;
    }
    // 清空Buffer实例
    void Clear() {
        reader_offset_ = 0;
        writer_offset_ = 0;
    }
    
private:
    std::vector<char> buffer_; // 缓冲区
    size_t reader_offset_; // 读偏移
    size_t writer_offset_; // 写偏移
};

#define BACKLOG 1024
class Socket {
public:
    Socket() : fd_(-1) {}
    Socket(int fd) : fd_(fd) {}
    int Fd() {
        return fd_;
    }
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
    bool Listen(int backlog = BACKLOG) {
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
            // recv缓冲区内没有数据时，此时去读会返回这两个错误
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            // 操作被信号打断
            if (errno == EINTR) {
                return 0;
            }
            // 真正发生错误了
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
            // send缓冲区内数据满时，此时去写会返回这两个错误
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            // 操作被信号打断
            if (errno == EINTR) {
                return 0;
            }
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
        if (!Create()) {
            return false;
        }
        if (flag && !SetNonBlock()) {
            return false;
        }
        if (!Bind(ip, port)) {
            return false;
        }
        if (!Listen()) {
            return false;
        }
        if (!SetAddressReuse()) {
            return false;
        }
        return true;
    }
    bool CreateClient(uint16_t port, const std::string &ip) {
        if (!Create()) {
            return false;
        }
        if (!Connect(ip, port)) {
            return false;
        }
        return true;
    }
    // 设置fd_地址重用
    bool SetAddressReuse() {
        int opt = 1;
        int ret = setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof opt);
        if (ret < 0) {
            return false;
        }
        return true;
    }
    // 设置fd_非阻塞
    bool SetNonBlock() {
        int flag = fcntl(fd_, F_GETFL, 0);
        if (flag < 0) {
            return false;
        }
        if (fcntl(fd_, F_SETFL, flag |= O_NONBLOCK) < 0) {
            return false;
        }
        return true;
    }
private:
    int fd_;
};

class EventLoop;
// 文件描述符的事件管理
using EventCallBack = std::function<void()>;
class Channel {
public:
    Channel(EventLoop *loop, int fd) : loop_(loop), fd_(fd), events_(0), revents_(0) {}
    int Fd() {
        return fd_;
    }
    // 获取要监控的事件（把想要监控的事件取出，当作epoll_wait的参数）
    uint32_t Events() {
        return events_;
    }
    // 将已经触发的事件设置进来（把epoll_wait被唤醒时触发的事件设置进来）
    void SetREvents(uint32_t revents) {
        revents_ = revents;
    }
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
    // 这两个函数会将channel中的events设置进epoll中
    void UpdateMonitor();
    void RemoveMonitor(); 
    // 事件的处理函数（一旦有事件触发，就调用该函数，该函数内部会调用相应的事件触发回调函数）
    // 当epoll_wait被唤醒时，就绪的事件会设置进revents中，channel再调用EventHandler就能够调用相应的事件触发回调函数
    void EventHandler() {
        if ((revents_ & EPOLLIN) || (revents_ & EPOLLRDHUP) || (revents_ & EPOLLPRI)) {
            if (any_callback_) {
                any_callback_();
            }
            if (read_callback_) {
                read_callback_();
            }
        }        
        if (revents_ & EPOLLOUT) {
            if (any_callback_) {
                any_callback_();
            }
            if (write_callback_) {
                write_callback_();
            }
        } else if (revents_ & EPOLLERR) {
            if (any_callback_) {
                any_callback_();
            }
            if (error_callback_) {
                error_callback_();
            }
        } else if (revents_ & EPOLLHUP) {
            if (any_callback_) {
                any_callback_();
            }
            if (close_callback_) {
                close_callback_();
            }
        }
    }

private:
    EventLoop *loop_;
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
    // 更新事件监控（将channel中设置的events设置进epoll中）
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
    // 移除事件监控（将channel曾经设置进epoll中的events拿掉）
    void RemoveEventMonitor(Channel *channel) {
        if (HasChannel(channel)) {
            channels_.erase(channel->Fd());
        }
        Update(channel, EPOLL_CTL_DEL);
    }
    // epoll开始监控，当epoll_wait被唤醒后，会将有事件触发的channel设置进active中
    // 外界再调用channel的EventHandler执行回调函数
    void Epoll(std::vector<Channel *> *active) {
        int nfds = epoll_wait(epfd_, events_, EPOLLEVENTS_NUMS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                return;
            }
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
        return channels_.find(channel->Fd()) != channels_.end();
    }
private:
    int epfd_;
    struct epoll_event events_[EPOLLEVENTS_NUMS];
    std::unordered_map<int, Channel *> channels_;    
};

using TimerTaskCallBack = std::function<void()>;
using TimerTaskRelease = std::function<void()>;
class TimerTask {
public:
    TimerTask(uint64_t id, 
              uint32_t timeout, 
              const TimerTaskCallBack &callback,
              const TimerTaskRelease &release)
        : id_(id)
        , timeout_(timeout)
        , callback_(callback)
        , release_(release)
        , is_cancel_(false) {}
    ~TimerTask() {
        if (!is_cancel_) {
            callback_();
        }
        release_();
    }
    uint32_t Timeout() {
        return timeout_;
    }
    void SetCancel() {
        is_cancel_ = true;
    }
    
private:
    uint64_t id_;
    uint32_t timeout_;
    TimerTaskCallBack callback_; 
    TimerTaskRelease release_;// 当析构函数执行时，会执行定时任务，这时在TimerWheel中映射的hash也要拿掉
    bool is_cancel_; 
};

using TaskSharedPtr = std::shared_ptr<TimerTask>;
using TaskWeakPtr = std::weak_ptr<TimerTask>;
class TimerWheel {
public:
    TimerWheel(EventLoop *loop)
        : loop_(loop)
        , timerfd_(CreateTimerfd())
        , timerfd_channel_(new Channel(loop_, timerfd_))
        , tick_(0)
        , capacity_(60)
        , wheel_(capacity_) {
        // 给timerfd注册一个读事件，用epoll监控
        timerfd_channel_->SetReadCallBack(std::bind(&TimerWheel::Ontime, this));
        timerfd_channel_->EnableMonitorRead();
    }
    // 将定时任务添加到时间轮中，顺便建立起id与TaskWeakPtr的映射关系
    void AddTimerTask(uint64_t id, uint32_t timeout, const TimerTaskCallBack &callback);
    // 通过id在timers_中找到对应的weakptr，通过这个weakptr构造一个sharedptr按照timeout再次添加到时间轮中
    void RefreshTimerTask(uint64_t id); 
    // 通过id在timers_中找到对应的weakptr，调用TimerTask里的取消方法 
    void CancelTimerTask(uint64_t id);
    // 将定时任务从timers_中拿掉
    void ReleaseTimerTask(uint64_t id);
    // 存在线程安全问题
    bool HasTimerTask(uint64_t id) {
        return timers_.find(id) != timers_.end();
    }
private:
    void AddTimerTaskInLoop(uint64_t id, 
                      uint32_t timeout, 
                      const TimerTaskCallBack &callback) {
        TaskSharedPtr tsp(new TimerTask(id, timeout, callback, 
                                            std::bind(&TimerWheel::ReleaseTimerTask, this, id)));
        timers_[id] = TaskWeakPtr(tsp);
        size_t pos = (tick_ + timeout) % capacity_;
        wheel_[pos].push_back(tsp);
    }
    void RefreshTimerTaskInLoop(uint64_t id) {
        auto it = timers_.find(id);
        if (it == timers_.end()) {
            return;
        }
        TaskSharedPtr tsp(it->second.lock());
        uint32_t timeout = tsp->Timeout();
        size_t pos = (tick_ + timeout) % capacity_;
        wheel_[pos].push_back(tsp);
    }
    void CancelTimerTaskInLoop(uint64_t id) {
        auto it = timers_.find(id);
        if (it == timers_.end()) {
            return;
        }
        TaskSharedPtr tsp(it->second.lock());
        if (tsp) tsp->SetCancel();
    }
    void ReleaseTimerTaskInLoop(uint64_t id) {
        auto it = timers_.find(id);
        if (it != timers_.end()) {
            timers_.erase(it);
        }
    }
    // 指针走一步，指针走到哪，就清空哪的内容（释放对象会调用析构函数）
    void Step() {
        tick_ = (tick_ + 1) % capacity_;
        wheel_[tick_].clear();
    }
    // 创建timerfd，让内核每隔1s就向timerfd中写入数据（以便唤醒epoll_wait，调用时间轮的回调函数，让指针走动，执行定时任务）
    static int CreateTimerfd() {
        int fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (fd < 0) {
            ERR_LOG("TIMERFD CREATE ERROR");
            abort();
        }        
        struct itimerspec itime;
        itime.it_value.tv_sec = 1;      // 第一次超时时间 1秒
        itime.it_value.tv_nsec = 0; 
        itime.it_interval.tv_sec = 1;   // 每次超时时间 1秒
        itime.it_interval.tv_nsec = 0;
        timerfd_settime(fd, 0, &itime, nullptr);
        return fd;
    }
    // 由于这里的epoll_wait是LT模式，所以必须要读走数据，防止事件一直触发
    int ReadTimerfd() {
        uint64_t times;
        int ret = read(timerfd_, &times, 8);
        if (ret < 0) {
            ERR_LOG("READ TIMERFD ERROR");
            abort();
        }
        return times;
    }
    // 当epoll_wait被唤醒时，读走timerfd，让指针走动（间隔1s）
    void Ontime() {
        int times = ReadTimerfd();
        for (int i = 0; i < times; ++i) {
            Step();
        }
    }

private:
    EventLoop *loop_;
    int timerfd_;
    std::unique_ptr<Channel> timerfd_channel_;
    size_t tick_;
    size_t capacity_;
    std::vector<std::vector<TaskSharedPtr>> wheel_;
    std::unordered_map<uint64_t, TaskWeakPtr> timers_;
};

using Functor = std::function<void()>;
class EventLoop {
public:
    EventLoop() : thread_id_(std::this_thread::get_id()) 
                , eventfd_(CreateEventfd())
                , eventfd_channel_(new Channel(this, eventfd_))
                , timer_wheel_(this) {
        eventfd_channel_->SetReadCallBack(std::bind(&EventLoop::ReadEventfd, this));
        eventfd_channel_->EnableMonitorRead();
    }
    void Run() {
        while (true) {
            std::vector<Channel *> actives;
            epoller_.Epoll(&actives);
            // 处理事件
            for (auto &channel : actives) {
                channel->EventHandler();
            }
            // 处理队列中的任务
            ExecQueueTask();
        }
    }
    // 执行任务
    // 假设用户开了好几个线程（或者是线程池），在执行相同的任务，那么就很可能设计到对临界资源的方位，导致线程不安全
    // 所以，将所有线程上的任务都集中到EventLoop线程上 
    // 每次执行任务的时候，先判断调用线程是否是EventLoop线程，若是就直接执行，若不是就压入队列，待合适的时机再执行
    void ExecTask (const Functor &task) {
        if (IsInLoop()) {
            // 如果当前线程是EventLoop线程，那么就直接执行任务
            task();
        } else {
            // 如果当前线程不是EventLOop线程，则将任务Push到任务队列中，有EventLoop线程统一执行
            PushTaskToQueue(task);
        }
    }
    // 将任务Push到队列中
    void PushTaskToQueue (const Functor &task) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            tasks_.push_back(task);
        }
        // 向eventfd中写入数据，触发epoller的读事件监控（唤醒epoller），防止epoller无法及时执行队列中的任务
        WriteEventfd();
    }
    // 判断当前线程是否是EventLoop线程
    bool IsInLoop() {
        return thread_id_ == std::this_thread::get_id();
    }
    void AssertInLoop() {
        assert(thread_id_ == std::this_thread::get_id());
    }
    // 更新事件监控
    void UpdateEventMonitor(Channel *channel) {
        epoller_.UpdateEventMonitor(channel);
    }
    // 移除事件监控
    void RemoveEventMonitor(Channel *channel) {
        epoller_.RemoveEventMonitor(channel);
    }
    void AddTimerTask(uint64_t id, uint32_t timeout, const TimerTaskCallBack &callback) {
        timer_wheel_.AddTimerTask(id, timeout, callback);
    }
    void RefreshTimerTask(uint64_t id) {
        timer_wheel_.RefreshTimerTask(id);
    } 
    void CancelTimerTask(uint64_t id) {
        timer_wheel_.CancelTimerTask(id);
    }
    void ReleaseTimerTask(uint64_t id) {
        timer_wheel_.ReleaseTimerTask(id);
    }
    bool HasTimerTask(uint64_t id) {
        return timer_wheel_.HasTimerTask(id);
    }
    
private:
    // 创建eventfd，为了能够给epoller提供读事件
    static int CreateEventfd() {
        int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (fd < 0) {
            ERR_LOG("CREATE EVENTFD ERROR");
            abort();
        }        
        return fd;
    }
    // 读出eventfd中的数据，防止epoller一直被唤醒
    void ReadEventfd() {
        uint64_t val = 0;
        int ret = read(eventfd_, &val, sizeof(val));
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR) return;
            ERR_LOG("READ EVENTFD ERROR");
            abort();
        }
    }
    // 向eventfd中写入数据，唤醒epoller
    void WriteEventfd() {
        uint64_t val = 1;
        int ret = write(eventfd_, &val, sizeof(val));
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR) return;
            ERR_LOG("WRITE EVENTFD ERROR");
            abort();
        }
    }
    // 执行队列中的任务
    void ExecQueueTask() {
        std::vector<Functor> tasks;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            tasks.swap(tasks_);
        }
        for (auto &task : tasks) task();
    }
private:
    std::thread::id thread_id_;    
    int eventfd_;
    std::unique_ptr<Channel> eventfd_channel_;
    Epoller epoller_;
    TimerWheel timer_wheel_;
    std::vector<Functor> tasks_;
    std::mutex mutex_;    
};

void Channel::UpdateMonitor() {
    loop_->UpdateEventMonitor(this);
}
void Channel::RemoveMonitor() {
    loop_->RemoveEventMonitor(this);
} 

void TimerWheel::AddTimerTask(uint64_t id, uint32_t timeout, const TimerTaskCallBack &callback) {
    loop_->ExecTask(std::bind(&TimerWheel::AddTimerTaskInLoop, this, id, timeout, callback));
}
void TimerWheel::RefreshTimerTask(uint64_t id) {
    loop_->ExecTask(std::bind(&TimerWheel::RefreshTimerTaskInLoop, this, id));
} 
void TimerWheel::CancelTimerTask(uint64_t id) {
    loop_->ExecTask(std::bind(&TimerWheel::CancelTimerTaskInLoop, this, id));
}
void TimerWheel::ReleaseTimerTask(uint64_t id) {
    loop_->ExecTask(std::bind(&TimerWheel::ReleaseTimerTaskInLoop, this, id));
}


/**
 * EventLoop实例化时就已经初始化了线程ID，也就是说EventLoop必须在线程内部实例化
 * 而在主从Reactor One Thread One Loop模型中，一个EventLoop对应一个线程
 * 假设先创建一批EventLoop再分配给其它线程，那么这是不对的（因为EventLoop实例化就已经初始化了线程ID）
 * 所以该模块的功能就是将EventLoop的实例化和线程绑定起来
 *      先创建线程
 *      然后在线程函数中实例化EventLoop
 */
class Loopthread {
public:
    Loopthread() : loop_(nullptr), thread_(std::thread(&Loopthread::ThreadEntry, this)) {}
    /*当有新连接到来时，需要获取到loop来初始化Connection*/
    EventLoop *Loop() {
        // 因为不能够确定loop的实例化会在loop的获取之前，所以有可能获取loop时会得到nullptr
        // 为了防止这种情况，也就是保证能够获取到有效的loop，所以用了mutex和cond
        EventLoop *loop = nullptr;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cond_.wait(lock, [&](){ return loop_ != nullptr; });
            loop = loop_;
        }
        return loop;
    }
private:
    void ThreadEntry() {
        EventLoop loop;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            loop_ = &loop;
            cond_.notify_all();
        }
        loop.Run();
    }
private:
    EventLoop *loop_; // 这里必须是指针，然后在线程函数内部初始化该指针。
    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable cond_;
};

/**
 * 本模块是对所有的LoopThread进行管理分配的
 * 主从Reactor中，主Reactor只负责获取新连接，从Reactor负责连接的事件监控及处理
 * 但如果某种场景需求较少，则只需要一个Reactor即可，所以此时从Reactor的数量可能为0（单Reactor服务器）
 */
class LoopThreadPool {
public:
    LoopThreadPool(EventLoop *base_loop) : size_(0), next_loop_(0), base_loop_(base_loop) {}
    void SetThreadLoopSize(int size) {
        size_ = size;
    }
    void Create() {
        if (size_ > 0) {
            threads_.resize(size_);
            loops_.resize(size_);
            for (int i = 0; i < size_; ++i) {
                threads_[i] = new Loopthread();
                loops_[i] = threads_[i]->Loop();
            }
        }
    }
    /*当有新连接到来时，需要获取到loop来初始化Connection*/
    EventLoop *Loop() {
        // 如果是单Reactor服务器，那么就返回base_loop
        if (size_ == 0) {
            return base_loop_;
        }
        next_loop_ = (next_loop_ + 1) % size_;
        return loops_[next_loop_];
    }
private:
    int size_; // 线程池的线程数量
    int next_loop_;
    EventLoop *base_loop_;
    std::vector<Loopthread *> threads_; 
    std::vector<EventLoop *> loops_; 
};

class Any {
private:
    class Holder {
    public:
        virtual ~Holder() {}
        virtual const std::type_info &Type() = 0;
        virtual Holder *clone() = 0;
    };
    template<class T>
    class PlaceHolder : public Holder {
    public:
        PlaceHolder(const T &val) : val_(val) {}
        const std::type_info &Type() { return typeid(T); }
        Holder *clone() { return new PlaceHolder(val_); }

        T val_;        
    };

    Holder *context_;
public:
    Any() : context_(nullptr) {}
    ~Any() { delete context_; }
    template<class T>
    Any(const T &val) : context_(new PlaceHolder<T>(val)) {}
    Any(const Any &other) : context_(nullptr == other.context_ ? nullptr : other.context_->clone()) {}
    Any &swap(Any &other) { std::swap(context_, other.context_); return *this;}
    template<class T>
    Any &operator=(const T &val) {
        Any(val).swap(*this);
        return *this;
    }
    Any &operator=(const Any &other) {
        Any(other).swap(*this);
        return *this;
    }
    template<class T>
    T *get() {
        assert(typeid(T) == context_->Type());
        return &(dynamic_cast<PlaceHolder<T> *>(context_))->val_;
    }
};

class Connection; 
typedef enum { CONNECTING, CONNECTED, DISCONNECTING, DISCONNECTED } ConnStatu;
using ConnectionSharedPtr = std::shared_ptr<Connection>;
using ConnectCallBack = std::function<void(const ConnectionSharedPtr &)>;
using MessageCallBack = std::function<void(const ConnectionSharedPtr &, Buffer *)>;
using CloseCallBack = std::function<void(const ConnectionSharedPtr &)>;
using AnyCallBack = std::function<void(const ConnectionSharedPtr &)>;
class Connection : public std::enable_shared_from_this<Connection> {
public:
    Connection(EventLoop *loop, int id, int fd)
        : loop_(loop)
        , id_(id)
        , fd_(fd)
        , enable_inactive_release_(false)
        , statu_(CONNECTING)
        , socket_(fd_)
        , channel_(loop_, fd_) {
        channel_.SetReadCallBack(std::bind(&Connection::Readhandler, this));
        channel_.SetWriteCallBack(std::bind(&Connection::WriteHandler, this));
        channel_.SetErrorCallBack(std::bind(&Connection::ErrorHandler, this));
        channel_.SetCloseCallBack(std::bind(&Connection::CloseHandler, this));
        channel_.SetAnyCallBack(std::bind(&Connection::AnyHandler, this));
    }
    int Id() { return id_; }
    int Fd() { return fd_; }
    bool IsConnected() { statu_ == CONNECTED; }
    Any *Context() { return &context_; }
    void SetContext(const Any &context) { context_ = context; }
    // 用户设置的任务回调函数 -- 当有连接到来，初始化Connection（Established函数）的时候被调用
    void SetConnectCallBack(const ConnectCallBack &connect_callback) {
        connect_callback_ = connect_callback;
    }
    // 用户设置的任务回调函数 -- 当channel的读事件触发后，数据被读取到ibuffer后，该函数被调用 
    void SetMessageCallBack(const MessageCallBack &message_callback) {
        message_callback_ = message_callback;
    }
    // 用户设置的任务回调函数 -- 当释放连接的时候（ReleaseInLoop函数），该函数被调用 
    void SetCloseCallBack(const CloseCallBack &close_callback) {
        close_callback_ = close_callback;
    }
    // 用户设置的任务回调函数 -- channel的任意事件被触发后（AnyHandler函数），该函数被调用 
    void SetAnyCallBack(const AnyCallBack &any_callback) {
        any_callback_ = any_callback;
    }
    // 用户设置的任务回调函数 -- 当释放连接的时候（ReleaseInLoop函数），该函数被调用
    void SetServerCloseCallBack(const CloseCallBack &server_close_callback) {
        server_close_callback_ = server_close_callback;
    }
    void Established() {
        loop_->ExecTask(std::bind(&Connection::EstablishedInLoop, this));
    }
    // 发送数据
    void Send(const char *buf, size_t len) {
        Buffer tmp;
        tmp.WriteAndPushOffSet(buf, len); 
        loop_->ExecTask(std::bind(&Connection::SendInLoop, this, tmp));
    }
    // 用户调用的函数统统Push到EventLoop线程中
    void Shutdown() {
        loop_->ExecTask(std::bind(&Connection::ShutdownInLoop, this));
    }
    void Release() {
        loop_->ExecTask(std::bind(&Connection::ReleaseInLoop, this));
    }
    void EnableInactiveRelease(int sec) {
        loop_->ExecTask(std::bind(&Connection::EnableInactiveReleaseInLoop, this, sec));
    }
    void DisableInactiveRelease() {
        loop_->ExecTask(std::bind(&Connection::DisableInactiveRelease, this));
    }
    // 非线程安全 --- 这个接口必须在EventLoop线程中立即调用
    // 防止新的事件触发后，处理的时候，协议还没有切换完成，导致按照原来的协议处理了
    // （假设我本来想执行的是协议后的message_callback，但由于协议还没切换完成，导致执行的是协议前的message_callback）
    void Upgrade(const Any &context,
                 const ConnectCallBack &connect_callback,
                 const MessageCallBack &message_callback,
                 const CloseCallBack &close_callback,
                 const AnyCallBack &any_callback,
                 const CloseCallBack &server_close_callback) {
        loop_->AssertInLoop();
        loop_->ExecTask(std::bind(&Connection::UpgradeInLoop, this, 
        context, connect_callback, message_callback, close_callback, any_callback, server_close_callback));
    }
private:
    // 五个channel回调函数
    // channel的读事件回调函数
    void Readhandler() {
        char buf[65536] = { 0 };
        ssize_t ret = socket_.RecvNonBlock(buf, sizeof(buf) - 1);
        if (ret < 0) {
            return ShutdownInLoop();
        } else if (ret == 0) {
            return;
        }
        ibuffer_.WriteAndPushOffSet(buf, ret);
        message_callback_(shared_from_this(), &ibuffer_);
    }
    // channel的写事件回调函数
    void WriteHandler() {
        ssize_t ret = socket_.SendNonBlock(obuffer_.ReaderPosition(), obuffer_.ReadableSize());
        if (ret < 0) {
            if (ibuffer_.ReadableSize() > 0) {
                message_callback_(shared_from_this(), &ibuffer_);
            }
            return ReleaseInLoop();
        }
        obuffer_.MoveReaderOffset(ret);
        if (obuffer_.ReadableSize() == 0) {
            channel_.DisableMonitorWriter();
            if (statu_ == DISCONNECTING) {
                ReleaseInLoop();
            }
        }
    }
    // channel的关闭事件回调函数
    void CloseHandler() {
        if (ibuffer_.ReadableSize() > 0) {
            message_callback_(shared_from_this(), &ibuffer_);
        }
        return ReleaseInLoop();
    }
    // channel的错误事件回调函数
    void ErrorHandler() {
        CloseHandler();
    }
    // channel的任意事件回调函数
    void AnyHandler() {
        if (enable_inactive_release_) {
            loop_->RefreshTimerTask(id_);       
        }
        if (any_callback_) {
            any_callback_(shared_from_this());
        }
    }
    // Connection启动初始化
    void EstablishedInLoop() {
        assert(statu_ == CONNECTING);
        statu_ = CONNECTED;
        channel_.EnableMonitorRead();
        if (connect_callback_) {
            connect_callback_(shared_from_this());
        }
    }
    // 发送数据
    void SendInLoop(Buffer buf) {
        if (statu_ == DISCONNECTED) return;
        obuffer_.WriteBufferAndPushOffSet(buf);
        if (!channel_.IsMonitorWriter()) {
            channel_.EnableMonitorWriter();
        }
    }
    // 供用户来进行关闭连接，但实际并不马上关闭，会先检查ibuffer和obuffer并适当的进行任务处理
    void ShutdownInLoop() {
        statu_ = DISCONNECTING;
        // 当输入缓冲区中有数据时，执行用户设置的message回调函数
        if (ibuffer_.ReadableSize() > 0) {
            if (message_callback_) {
                message_callback_(shared_from_this(), &ibuffer_);
            }
        }
        // 当输出缓冲区中有数据时，打开写事件监控（当写事件就绪时，会自动将输出缓冲区中的数据写出）
        if (obuffer_.ReadableSize() > 0) {
            if (!channel_.IsMonitorWriter()) {
                channel_.EnableMonitorWriter();
            }
        }
        // 当输出缓冲区中无数据时（此时ibuffer以处理完毕），真的关闭连接
        if (obuffer_.ReadableSize() == 0) {
            ReleaseInLoop();
        }
    }
    // 真的关闭连接
    void ReleaseInLoop() {
        // 修改状态为已关闭 -- DISCONNECTED
        statu_ = DISCONNECTED;
        // 移除该连接（fd）上的所有监控事件
        channel_.RemoveMonitor();
        // 关闭fd
        socket_.Close();
        // 取消定时任务（非活跃连接销毁任务）
        if (loop_->HasTimerTask(id_)) {
            DisableInactiveReleaseInLoop();
        }
        // 执行close回调函数
        if (close_callback_) {
            close_callback_(shared_from_this());
        }
        // 执行server_close回调函数
        if (server_close_callback_) {
            server_close_callback_(shared_from_this());
        }
    }
    // 开启非活跃连接销毁任务
    void EnableInactiveReleaseInLoop(int sec) {
        enable_inactive_release_ = true;
        if (loop_->HasTimerTask(id_)) {
            loop_->RefreshTimerTask(id_);
        } else {
            loop_->AddTimerTask(id_, sec, std::bind(&Connection::ReleaseInLoop, this));
        }
    }
    // 关闭非活跃连接销毁任务
    void DisableInactiveReleaseInLoop() {
        enable_inactive_release_ = false;
        if (loop_->HasTimerTask(id_)) {
            loop_->CancelTimerTask(id_);
        }
    }
    // 升级协议（就是将所有用户一开始设置的各种回调任务重新设置一遍）
    void UpgradeInLoop(const Any &context,
                 const ConnectCallBack &connect_callback,
                 const MessageCallBack &message_callback,
                 const CloseCallBack &close_callback,
                 const AnyCallBack &any_callback,
                 const CloseCallBack &server_close_callback) {
        context_ = context;
        connect_callback_ = connect_callback;
        message_callback_ = message_callback;
        close_callback_ = close_callback;
        any_callback_ = any_callback;
        server_close_callback_ = server_close_callback;
    }
private:
    EventLoop *loop_; // 连接所关联的EventLoop
    int id_; // 连接ID
    int fd_; // 文件描述符
    bool enable_inactive_release_; // 开启非活跃连接销毁 
    ConnStatu statu_;// 连接所处的状态
    Socket socket_;  // fd_的管理
    Channel channel_;// 连接事件的管理
    Buffer ibuffer_; // 输入缓冲区
    Buffer obuffer_; // 输出缓冲区
    Any context_;    // 上下文管理
    ConnectCallBack connect_callback_;
    MessageCallBack message_callback_;
    CloseCallBack close_callback_;
    AnyCallBack any_callback_;
    CloseCallBack server_close_callback_;
};


// 主线程Reactor，专门用来接收连接
using AcceptorCallBack = std::function<void(int)>;
class Acceptor 
{
public:
    Acceptor(EventLoop *loop, int port)
        : loop_(loop)
        , socket_(CreateServer(port))
        , channel_(loop_, socket_.Fd()) {
        channel_.SetReadCallBack(std::bind(&Acceptor::ReadHandler, this));
    }
    void ReadHandler() {
        int fd = socket_.Accept();
        if (fd < 0) {
            return;
        }
        if (callback_) {
            callback_(fd);
        }
    }
    void SetReadCallBack(const AcceptorCallBack &callback) {
        callback_ = callback;
    }   
    void Listen() {
        // 该函数不能放在构造函数中，因为启动读监控后，可能立马就会有连接到来，但此时还可能并未设置callback
        channel_.EnableMonitorRead();
    }
private:
    int CreateServer(int port) {
        bool ret = socket_.CreateServer(port);
        assert(ret);
        return socket_.Fd();
    }
private:
    EventLoop *loop_;
    Socket socket_;
    Channel channel_;
    AcceptorCallBack callback_;
};


class TcpServer {
public:
    TcpServer(int port)
        : port_(port)
        , next_connid_(0)
        , next_timerid_(0)
        , timeout_(0)
        , enable_inactive_release_(false)
        , acceptor_(&baseloop_, port_)
        , pool_(&baseloop_) {
        acceptor_.SetReadCallBack(std::bind(&TcpServer::NewConnection, this, std::placeholders::_1));
        acceptor_.Listen();
    }
    void SetConnectCallBack(const ConnectCallBack &connect_callback) {
        connect_callback_ = connect_callback;
    }
    void SetMessageCallBack(const MessageCallBack &message_callback) {
        message_callback_ = message_callback;
    }
    void SetCloseCallBack(const CloseCallBack &close_callback) {
        close_callback_ = close_callback;
    }
    void SetAnyCallBack(const AnyCallBack &any_callback) {
        any_callback_ = any_callback;
    }
    void SetThreadLoopSize(int size) {
        pool_.SetThreadLoopSize(size);
    }
    void EnableInactiveRelease(int timeout) {
        timeout_ = timeout;
        enable_inactive_release_ = true;
    }
    void AddTimerTask(const Functor &task, int timeout) {
        baseloop_.ExecTask(std::bind(&TcpServer::AddTimerTaskInLoop, this, task, timeout));
    }
    void Run() {
        pool_.Create();
        baseloop_.Run();
    }
private:
    void NewConnection(int fd) {
        ++next_connid_;
        ConnectionSharedPtr conn(new Connection(pool_.Loop(), next_connid_, fd));
        conn->SetMessageCallBack(message_callback_);
        conn->SetConnectCallBack(connect_callback_);
        conn->SetCloseCallBack(close_callback_);
        conn->SetAnyCallBack(any_callback_);
        conn->SetServerCloseCallBack(std::bind(&TcpServer::ReleaseConnection, this, std::placeholders::_1));
        if (enable_inactive_release_) {
            conn->EnableInactiveRelease(10);
        }
        conn->Established();
        conns_[next_connid_] = conn;
    }
    void AddTimerTaskInLoop(const Functor &task, int timeout) {
        next_timerid_++;
        baseloop_.AddTimerTask(next_timerid_, timeout, task);
    }
    void ReleaseConnectionInLoop(const ConnectionSharedPtr &conn) {
        auto it = conns_.find(conn->Id());
        if (it != conns_.end()) {
            conns_.erase(it);
        }
    }
    void ReleaseConnection(const ConnectionSharedPtr &conn) {
        baseloop_.ExecTask(std::bind(&TcpServer::ReleaseConnectionInLoop, this, conn));
    }
private:
    int port_;
    int next_connid_;
    int next_timerid_;
    int timeout_;
    bool enable_inactive_release_;
    EventLoop baseloop_;
    Acceptor acceptor_;
    LoopThreadPool pool_;
    std::unordered_map<uint64_t, ConnectionSharedPtr> conns_;
    ConnectCallBack connect_callback_;
    MessageCallBack message_callback_;
    CloseCallBack close_callback_;
    AnyCallBack any_callback_;
};

class NetWork {
public:
    NetWork() {
        signal(SIGPIPE, SIG_IGN);
    }
};
static NetWork nw;

#endif // __SERVER_HPP__