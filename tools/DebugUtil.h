#pragma once

#include <iostream>
#include <string>

// #define DEBUG_PRINT(...) debug::print("\033[30m", __LINE__, "\033[0m", " ", "\033[0;36m", __PRETTY_FUNCTION__, "\033[0m", ": ", __VA_ARGS__)
// #define DEBUG_PRINT(...) debug::print(__LINE__, " ", __PRETTY_FUNCTION__, ": ", __VA_ARGS__)
#define DEBUG_PRINT(...) debug::print(__VA_ARGS__)

namespace debug {
    inline void print() {
        // Base case for recursion, adds newline
        std::cout << "\n";
    }

    template<typename T, typename... Args>
    inline void print(const T& first, const Args&... args) {
        std::cout << first << "";
        print(args...); // Recursive call with the rest of the arguments.
    }
}

