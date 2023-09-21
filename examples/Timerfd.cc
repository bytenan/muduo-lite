#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/timerfd.h>

int main() {

    int timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timerfd < 0) {
        printf("timerf_create error\n");
        exit(-1);
    }
    struct itimerspec itime;
    itime.it_value.tv_sec = 3;      // 第一次超时时间 3秒
    itime.it_value.tv_nsec = 0; 
    itime.it_interval.tv_sec = 1;   // 每次超时时间 1秒
    itime.it_interval.tv_nsec = 0;
    int ret = timerfd_settime(timerfd, 0, &itime, nullptr);
    if (ret < 0) {
        printf("timerfd_settime error\n");
        exit(-1);
    }
    printf("%ld\n", time(nullptr));
    while (true) {
        uint64_t times;
        int n = read(timerfd, &times, 8);
        if (n > 0) {
            printf("%ld\n", time(nullptr));
        }
    }

    return 0;
}