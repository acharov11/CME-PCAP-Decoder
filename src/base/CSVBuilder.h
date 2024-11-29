//
// Created by hruks on 11/26/2024.
//

#ifndef CSVBUILDER_H
#define CSVBUILDER_H


#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>

class CSVBuilder {
private:
    std::ofstream csv_file_;
    bool has_header_ = false;

public:
    // Constructor to initialize the CSV file
    explicit CSVBuilder(const std::string& filename) {
        csv_file_.open(filename, std::ios::out | std::ios::trunc);
        if (!csv_file_.is_open()) {
            throw std::runtime_error("Failed to open CSV file: " + filename);
        }
    }

    // Destructor to close the file
    ~CSVBuilder() {
        if (csv_file_.is_open()) {
            csv_file_.close();
        }
    }

    // Write header row
    void write_header(const std::vector<std::string>& header) {
        if (has_header_) {
            throw std::runtime_error("Header has already been written!");
        }
        write_row(header);
        has_header_ = true;
    }

    // Write a single row to the CSV
    void write_row(const std::vector<std::string>& row) {
        if (!csv_file_.is_open()) {
            throw std::runtime_error("CSV file is not open!");
        }
        for (size_t i = 0; i < row.size(); ++i) {
            csv_file_ << row[i];
            if (i < row.size() - 1) {
                csv_file_ << ",";
            }
        }
        csv_file_ << "\n";
    }

    // Write a single row to an existing open file stream
    void write_row(std::ofstream& file_stream, const std::vector<std::string>& row) {
        if (!file_stream.is_open()) {
            throw std::runtime_error("File stream is not open!");
        }
        for (size_t i = 0; i < row.size(); ++i) {
            file_stream << row[i];
            if (i < row.size() - 1) {
                file_stream << ",";
            }
        }
        file_stream << "\n";
    }


    // Write multiple rows to the CSV
    void write_rows(const std::vector<std::vector<std::string>>& rows) {
        for (const auto& row : rows) {
            write_row(row);
        }
    }

    // Flush the CSV buffer to file
    void flush() {
        if (!csv_file_.is_open()) {
            throw std::runtime_error("CSV file is not open!");
        }
        csv_file_.flush();
    }
};


#endif //CSVBUILDER_H
