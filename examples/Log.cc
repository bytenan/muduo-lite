#include <iostream>
#include <cstdio>
#include <ctime>

#define INF 0
#define DBG 1
#define ERR 2
#define LOG_LEVEL DBG

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

int main() {

    INF_LOG("hello wolrd - INF");
    DBG_LOG("hello wolrd - DBG");
    ERR_LOG("hello wolrd - ERR");
    
    return 0;
}
