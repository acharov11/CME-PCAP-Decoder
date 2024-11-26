//
// Created by Anton Charov on 11/23/2024.
//

#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>

class Logger {
public:
    enum LogLevel { DEBUG = 0, INFO, WARNING, ERROR, FOCUS, MAX_LOG_LEVELS };

    Logger(bool log_to_file = false, const std::string& file_name = "")
        : log_to_file(log_to_file) {
        std::fill(std::begin(enabled_levels), std::end(enabled_levels), false);
        // enable_level(INFO);
        // enable_level(ERROR);

        if (log_to_file) {
            log_file.open(file_name, std::ios::app);
            if (!log_file.is_open()) {
                throw std::runtime_error("Unable to open log file: " + file_name);
            }
        }
    }

    ~Logger() {
        if (log_to_file && log_file.is_open()) {
            log_file.close();
        }
    }

    void log(LogLevel level, const std::string& message) {
        if (is_level_enabled(level)) {
            std::lock_guard<std::mutex> lock(mutex);
            std::ostream& output = (log_to_file && log_file.is_open()) ? log_file : std::cout;
            output << "[" << log_level_to_string(level) << "] " << message << std::endl;
        }
    }

    void enable_level(LogLevel level) {
        if (level < MAX_LOG_LEVELS) {
            enabled_levels[level] = true;
        }
    }

    void disable_level(LogLevel level) {
        if (level < MAX_LOG_LEVELS) {
            enabled_levels[level] = false;
        }
    }

    bool is_level_enabled(LogLevel level) const {
        return level < MAX_LOG_LEVELS && enabled_levels[level];
    }

private:
    bool enabled_levels[MAX_LOG_LEVELS];
    bool log_to_file;
    std::ofstream log_file;
    std::mutex mutex;

    std::string log_level_to_string(LogLevel level) {
        switch (level) {
            case DEBUG: return "DEBUG";
            case INFO: return "INFO";
            case WARNING: return "WARNING";
            case ERROR: return "ERROR";
            case FOCUS: return "FOCUS";
            default: return "UNKNOWN";
        }
    }
};



#endif //LOGGER_H
