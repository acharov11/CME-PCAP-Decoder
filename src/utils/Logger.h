#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>

class Logger {
public:
    enum LogLevel { DEBUG = 0, INFO, WARNING, ERROR, FOCUS, EXTRACT_DEBUG, MAX_LOG_LEVELS };

    Logger(bool log_to_file = false, const std::string& file_name = "")
        : log_to_file_(log_to_file) {
        std::fill(std::begin(enabled_levels_), std::end(enabled_levels_), false);

        if (log_to_file_) {
            log_file_.open(file_name, std::ios::app);
            if (!log_file_.is_open()) {
                throw std::runtime_error("Unable to open log file: " + file_name);
            }
        }
    }

    ~Logger() {
        if (log_to_file_ && log_file_.is_open()) {
            log_file_.close();
        }
    }

    // Core logging method
    void log(LogLevel level, const std::string& message) {
        if (enabled_levels_[level]) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::ostream& output = (log_to_file_ && log_file_.is_open()) ? log_file_ : std::cout;

            if (enable_color_ && !log_to_file_) {
                output << color_for_level(level); // Add color if logging to console
            }

            output << "[" << log_level_to_string(level) << "] " << message;

            if (enable_color_ && !log_to_file_) {
                output << "\033[0m"; // Reset color after the message
            }

            output << std::endl;
        }
    }

    // Simplified helper methods
    void debug(const std::string& message) { log(DEBUG, message); }
    void info(const std::string& message) { log(INFO, message); }
    void warning(const std::string& message) { log(WARNING, message); }
    void error(const std::string& message) { log(ERROR, message); }
    void focus(const std::string& message) { log(FOCUS, message); }
    void extract_debug(const std::string& message) { log(EXTRACT_DEBUG, message); }

    // Enable a specific log level
    void enable_level(LogLevel level) {
        if (level < MAX_LOG_LEVELS) {
            enabled_levels_[level] = true;
        }
    }

    // Disable a specific log level
    void disable_level(LogLevel level) {
        if (level < MAX_LOG_LEVELS) {
            enabled_levels_[level] = false;
        }
    }

    // Check if a log level is enabled
    bool is_level_enabled(LogLevel level) const {
        return enabled_levels_[level];
    }

private:
    bool enabled_levels_[MAX_LOG_LEVELS];
    bool log_to_file_;
    bool enable_color_ = false;
    std::ofstream log_file_;
    std::mutex mutex_;

    // ANSI color codes for each log level
    std::string color_for_level(LogLevel level) const {
        switch (level) {
            case DEBUG: return "\033[36m"; // Cyan
            case INFO: return "\033[32m"; // Green
            case WARNING: return "\033[33m"; // Yellow
            case ERROR: return "\033[31m"; // Red
            case FOCUS: return "\033[35m"; // Magenta
            case EXTRACT_DEBUG: return "\033[36m"; // Cyan
            default: return "\033[0m";    // Reset
        }
    }

    // Convert log level to string for display
    std::string log_level_to_string(LogLevel level) const {
        switch (level) {
            case DEBUG: return "DEBUG";
            case INFO: return "INFO";
            case WARNING: return "WARNING";
            case ERROR: return "ERROR";
            case FOCUS: return "FOCUS";
            case EXTRACT_DEBUG: return "EXTRACT_DEBUG";
            default: return "UNKNOWN";
        }
    }
};

#endif // LOGGER_H
