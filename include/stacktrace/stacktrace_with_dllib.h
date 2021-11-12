#pragma once

#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <link.h>
#include <sys/wait.h>

#include <array>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

// copy from https://github.com/MisterTea/UniversalStacktrace
namespace stacktrace_dl {

namespace internal {

template <typename Out>
inline void Split(const std::string &s, char delim, Out result) {
  std::stringstream ss;
  ss.str(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    *(result++) = item;
  }
}

inline std::vector<std::string> Split(const std::string &s, char delim) {
  std::vector<std::string> elems;
  Split(s, delim, std::back_inserter(elems));
  return elems;
}

// Needed for calling addr2line / atos
inline std::string SystemToStr(const char *cmd) {
  std::array<char, 128> buffer{};
  std::string result;
  FILE *pipe = popen(cmd, "r");
  if (!pipe) {
    throw std::runtime_error("popen() failed!");
  }
  while (!feof(pipe)) {
    if (fgets(buffer.data(), 128, pipe) != nullptr) result += buffer.data();
  }
  auto closeValue = pclose(pipe);
  auto exitCode = WEXITSTATUS(closeValue);
  if (exitCode) {
    return "";
  }
  return result;
}

inline std::string address2string(uint64_t address) {
  std::ostringstream ss;
  ss << "0x" << std::hex << uint64_t(address);
  return ss.str();
}

struct StackTraceEntry {
  StackTraceEntry(int _stackIndex, std::string _address,
                  std::string _binaryFileName, std::string _functionName,
                  std::string _sourceFileName, int _lineNumber)
      : stack_index(_stackIndex),
        address(std::move(_address)),
        binary_file_name(std::move(_binaryFileName)),
        function_name(std::move(_functionName)),
        source_file_name(std::move(_sourceFileName)),
        line_number(_lineNumber) {}

  inline std::string to_string() const {
    std::string str;
    str += "#" + std::to_string(stack_index);
    str += " " + std::string(basename(binary_file_name.c_str())) + "(+" +
           address + ")";
    str += " " + function_name;
    if (line_number > 0) {
      str += " (" + std::string(basename(source_file_name.c_str())) + ":" +
             std::to_string(line_number) + ")";
    }
    return str;
  }

  int stack_index;
  std::string address;
  std::string binary_file_name;
  std::string function_name;
  std::string source_file_name;
  int line_number;
};

}  // namespace internal

class StackTrace {
 public:
  explicit StackTrace(std::vector<internal::StackTraceEntry> _entries)
      : entries_(std::move(_entries)) {}

  inline std::string to_string() {
    std::string str;
    for (const auto &it : entries_) {
      str += it.to_string() + "\n";
    }
    return str;
  }

 private:
  std::vector<internal::StackTraceEntry> entries_;
};

// Linux uses backtrace() + addr2line
inline StackTrace Generate() {
  // Libunwind and some other functions aren't thread safe.
  static std::mutex mtx;
  static constexpr int MAX_STACK_FRAMES = 64;

  std::lock_guard<std::mutex> lock(mtx);

  void *stack_raw[MAX_STACK_FRAMES];
  int num_frames = backtrace(stack_raw, MAX_STACK_FRAMES);

  // Discard the current stack frame
  void **stack = &stack_raw[1];
  num_frames -= 1;

  std::vector<internal::StackTraceEntry> stack_trace;
  for (int a = 0; a < num_frames; ++a) {
    std::string addr;
    std::string file_name;
    std::string function_name;

    Dl_info dl_info;
    struct link_map *map;

    // On success, dladdr() return a nonzero value.
    if (0 != dladdr1(stack[a], &dl_info, reinterpret_cast<void **>(&map),
                     RTLD_DL_LINKMAP)) {
      // Convert filename to canonical path
      if (dl_info.dli_fname && dl_info.dli_fname[0] != '\0') {
        char *buf = ::realpath(dl_info.dli_fname, nullptr);
        file_name = buf ? buf : "";
        free(buf);

        // ref:
        // https://code.woboq.org/userspace/glibc/debug/backtracesyms.c.html
        // glibc/debug/backtracesyms.c::62
        dl_info.dli_fbase = reinterpret_cast<void *>(map->l_addr);
      }

      // Make address relative to process start
      addr = internal::address2string(uint64_t(stack[a]) -
                                      (uint64_t)dl_info.dli_fbase);
      function_name = dl_info.dli_sname ? dl_info.dli_sname : "";
    } else {
      addr = internal::address2string(uint64_t(stack[a]));
    }

    // Perform demangling if parsed properly
    if (!function_name.empty()) {
      int status = 0;
      auto demangled_function_name =
          abi::__cxa_demangle(function_name.data(), nullptr, nullptr, &status);
      // if demangling is successful, output the demangled function name
      if (status == 0) {
        // Success (see
        // http://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html)
        function_name = std::string(demangled_function_name);
      }
      if (demangled_function_name) {
        free(demangled_function_name);
      }
    }
    internal::StackTraceEntry entry(a, addr, file_name, function_name, "", -1);
    stack_trace.push_back(entry);
  }

  // Fetch source file & line numbers
  std::map<std::string, std::list<std::string> > file_addresses;
  std::map<std::string, std::list<std::string> > file_data;
  for (const auto &it : stack_trace) {
    if (it.binary_file_name.length()) {
      if (file_addresses.find(it.binary_file_name) == file_addresses.end()) {
        file_addresses[it.binary_file_name] = {};
      }
      file_addresses.at(it.binary_file_name).push_back(it.address);
    }
  }
  for (const auto &it : file_addresses) {
    std::string fileName = it.first;
    std::ostringstream ss;
    ss << "addr2line -C -f -p -e " << fileName << " ";
    for (const auto &it2 : it.second) {
      ss << it2 << " ";
    }
    ss << " 2>/dev/null"; // Turn off error output

    auto addrLineOutput = internal::SystemToStr(ss.str());
    if (addrLineOutput.length()) {
      auto outputLines = internal::Split(addrLineOutput, '\n');
      file_data[fileName] =
          std::list<std::string>(outputLines.begin(), outputLines.end());
    }
  }
  std::regex addr_to_line_regex("^(.+?) at (.+):([0-9]+)");
  for (auto &it : stack_trace) {
    if (it.binary_file_name.length() &&
        file_data.find(it.binary_file_name) != file_data.end()) {
      std::string output_line = file_data.at(it.binary_file_name).front();
      file_data.at(it.binary_file_name).pop_front();
      if (output_line == std::string("?? ??:0")) {
        continue;
      }
      std::smatch matches;
      if (regex_search(output_line, matches, addr_to_line_regex)) {
        it.function_name = matches[1];
        it.source_file_name = matches[2];
        it.line_number = std::stoi(matches[3]);
      }
    }
  }

  return StackTrace(stack_trace);
}

}  // namespace stacktrace_dl
