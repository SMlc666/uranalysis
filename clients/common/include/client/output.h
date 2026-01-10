#pragma once

#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace client {

class Output {
public:
    virtual ~Output() = default;
    virtual void write_line(const std::string& line) = 0;
};

class StdoutOutput : public Output {
public:
    void write_line(const std::string& line) override;
};

class FileOutput : public Output {
public:
    explicit FileOutput(const std::string& path, bool append = false);
    ~FileOutput() override;
    
    bool is_open() const;
    void write_line(const std::string& line) override;

private:
    std::ofstream file_;
};

class StringOutput : public Output {
public:
    void write_line(const std::string& line) override;
    std::string get_output() const;
    void clear();

private:
    std::ostringstream buffer_;
};

// Parse redirection and pipe from command line
// Supports: command > file, command >> file, command | external_cmd
struct RedirectInfo {
    std::string command;           // Command without redirection/pipe
    std::string redirect_path;     // Path to redirect to (empty if no redirection)
    std::string pipe_command;      // External command to pipe to (empty if no pipe)
    bool append = false;           // true for >>, false for >
};

RedirectInfo parse_redirect(const std::string& line);

// Execute an external command with input, returns the exit code
// On Windows uses _popen, on POSIX uses popen
int execute_external_command(const std::string& command, const std::string& input);

}  // namespace client
