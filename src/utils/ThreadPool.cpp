#include "ThreadPool.h"

// Constructor: Initialize thread pool with the specified number of threads
ThreadPool::ThreadPool(size_t num_threads) : stop(false) {
    for (size_t i = 0; i < num_threads; ++i) {
        // Create threads that wait for tasks and execute them
        workers.emplace_back([this] {
            while (true) {
                std::function<void()> task;

                {
                    // Wait for a task to be available or stop signal
                    std::unique_lock<std::mutex> lock(queue_mutex);
                    condition.wait(lock, [this] { return stop || !tasks.empty(); });

                    // If stopping and no tasks remain, exit the thread
                    if (stop && tasks.empty()) return;

                    // Retrieve the next task
                    task = std::move(tasks.front());
                    tasks.pop();
                }

                // Execute the task
                task();
            }
        });
    }
}

// Destructor: Stop all threads and join them
ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop = true; // Signal threads to stop
    }
    condition.notify_all(); // Wake up all threads to finish execution
    for (std::thread &worker : workers) {
        worker.join(); // Wait for thread completion
    }
}

// Enqueue a new task
void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        tasks.push(std::move(task)); // Add task to the queue
    }
    condition.notify_one(); // Notify one thread
}
