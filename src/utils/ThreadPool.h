#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads);
    ~ThreadPool();

    void enqueue(std::function<void()> task);

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

#endif // THREADPOOL_H
