#include "client/output.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#define popen _popen
#define pclose _pclose
#endif

namespace client {

void StdoutOutput::write_line(const std::string& line) {
    std::cout << line << "\n";
}

FileOutput::FileOutput(const std::string& path, bool append)
    : file_(path, append ? (std::ios::out | std::ios::app) : std::ios::out) {
}

FileOutput::~FileOutput() {
    if (file_.is_open()) {
        file_.close();
    }
}

bool FileOutput::is_open() const {
    return file_.is_open();
}

void FileOutput::write_line(const std::string& line) {
    if (file_.is_open()) {
        file_ << line << "\n";
    }
}

void StringOutput::write_line(const std::string& line) {
    buffer_ << line << "\n";
}

std::string StringOutput::get_output() const {
    return buffer_.str();
}

void StringOutput::clear() {
    buffer_.str("");
    buffer_.clear();
}

namespace {

std::string trim(const std::string& s) {
    std::size_t start = s.find_first_not_of(" \t");
    if (start == std::string::npos) {
        return "";
    }
    std::size_t end = s.find_last_not_of(" \t");
    return s.substr(start, end - start + 1);
}

}  // namespace

RedirectInfo parse_redirect(const std::string& line) {
    RedirectInfo info;
    
    // Look for | first (pipe)
    std::size_t pipe_pos = line.find('|');
    if (pipe_pos != std::string::npos) {
        info.command = trim(line.substr(0, pipe_pos));
        info.pipe_command = trim(line.substr(pipe_pos + 1));
        return info;
    }
    
    // Look for >> (append mode)
    std::size_t pos = line.find(">>");
    if (pos != std::string::npos) {
        info.append = true;
        info.command = trim(line.substr(0, pos));
        info.redirect_path = trim(line.substr(pos + 2));
        return info;
    }
    
    // Look for > (overwrite mode)
    pos = line.find('>');
    if (pos != std::string::npos) {
        info.append = false;
        info.command = trim(line.substr(0, pos));
        info.redirect_path = trim(line.substr(pos + 1));
        return info;
    }
    
    // No redirection or pipe
    info.command = line;
    return info;
}

int execute_external_command(const std::string& command, const std::string& input) {
    // Create a temporary file to hold the input
    // This is a simple approach that works across platforms
    
#ifdef _WIN32
    // On Windows, use echo with pipe
    std::string full_command = "echo " + input + " | " + command;
    // Actually, this doesn't work well with multi-line input
    // Use a different approach: write to temp file and use type
    
    // Create temp file
    char temp_path[MAX_PATH];
    char temp_file[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_path);
    GetTempFileNameA(temp_path, "ura", 0, temp_file);
    
    // Write input to temp file
    {
        std::ofstream out(temp_file);
        out << input;
    }
    
    // Execute command with input from temp file
    std::string cmd = "type \"" + std::string(temp_file) + "\" | " + command;
    int result = std::system(cmd.c_str());
    
    // Clean up temp file
    DeleteFileA(temp_file);
    
    return result;
#else
    // On POSIX, we can use popen with "w" mode to write to stdin
    FILE* pipe = popen(command.c_str(), "w");
    if (!pipe) {
        std::cerr << "Error: failed to execute: " << command << "\n";
        return -1;
    }
    
    // Write input to the pipe
    fwrite(input.c_str(), 1, input.size(), pipe);
    
    return pclose(pipe);
#endif
}

}  // namespace client
