#include <iostream>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <unistd.h>

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
        if (!is_cancel_) callback_();
        release_();
    }
    uint32_t Timeout() { return timeout_; }
    void SetCancel() { is_cancel_ = true; }
    
private:
    uint64_t id_;
    uint32_t timeout_;
    TimerTaskCallBack callback_; 
    TimerTaskRelease release_;
    bool is_cancel_; 
};

using TaskSharedPtr = std::shared_ptr<TimerTask>;
using TaskWeakPtr = std::weak_ptr<TimerTask>;
class TimeWheel {
public:
    TimeWheel() : tick_(0), capacity_(60), wheel_(capacity_) {}
    void AddTimerTask(uint64_t id, 
                      uint32_t timeout, 
                      const TimerTaskCallBack &callback) {
        TaskSharedPtr tsp(new TimerTask(id, timeout, callback, 
                                            std::bind(&TimeWheel::ReleaseTimerTask, this, id)));
        timers_[id] = TaskWeakPtr(tsp);
        size_t pos = (tick_ + timeout) % capacity_;
        wheel_[pos].push_back(tsp);
    }
    void RefreshTimerTask(uint64_t id) {
        auto it = timers_.find(id);
        if (it == timers_.end()) return;
        TaskSharedPtr tsp(it->second.lock());
        uint32_t timeout = tsp->Timeout();
        size_t pos = (tick_ + timeout) % capacity_;
        wheel_[pos].push_back(tsp);
    }
    void CancelTimerTask(uint64_t id) {
        auto it = timers_.find(id);
        if (it == timers_.end()) return;
        TaskSharedPtr tsp(it->second.lock());
        if (tsp) tsp->SetCancel();
    }
    void ReleaseTimerTask(uint64_t id) {
        auto it = timers_.find(id);
        if (it == timers_.end()) return;
        timers_.erase(it);
    }
    void Step() {
        tick_ = (tick_ + 1) % capacity_;
        wheel_[tick_].clear();
    }
private:
    size_t tick_;
    size_t capacity_;
    std::vector<std::vector<TaskSharedPtr>> wheel_;
    std::unordered_map<uint64_t, TaskWeakPtr> timers_;
};

class Test {
public:
    Test() { std::cout << "Test()" << std::endl; }
    ~Test() { std::cout << "~Test()" << std::endl; }
};

void Del(Test *p) {
    delete p;
}

int main() {

    Test *p = new Test();
    TimeWheel tw;
    tw.AddTimerTask(888, 5, std::bind(Del, p));
    for (int i = 0; i < 5; ++i) {
        sleep(1);
        std::cout << "------------------" << std::endl;
        tw.RefreshTimerTask(888);
        tw.Step();
    } 
    tw.CancelTimerTask(888);
    while (true) {
        sleep(1);
        std::cout << "++++++++++++++++++" << std::endl;  
        tw.Step();
    }

    return 0;
}