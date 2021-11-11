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
inline void split(const std::string &s, char delim, Out result) {
  std::stringstream ss;
  ss.str(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    *(result++) = item;
  }
}

inline std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> elems;
  split(s, delim, std::back_inserter(elems));
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

inline std::string addressToString(uint64_t address) {
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
    str += "#" + std::to_string(stack_index) + " " + address;
    if (!function_name.empty()) {
      str += " " + function_name;
    }
    if (line_number > 0) {
      std::string sourceFileNameCopy = source_file_name;
      str += " (" + std::string(basename(&sourceFileNameCopy[0])) + ":" +
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
static const int MAX_STACK_FRAMES = 64;
inline StackTrace generate() {
  // Libunwind and some other functions aren't thread safe.
  static std::mutex mtx;

  std::lock_guard<std::mutex> lock(mtx);

  void *stack[MAX_STACK_FRAMES];
  int numFrames = backtrace(stack, MAX_STACK_FRAMES);
  memmove(stack, stack + 1, sizeof(void *) * (numFrames - 1));
  numFrames--;

  std::vector<internal::StackTraceEntry> stackTrace;
  for (int a = 0; a < numFrames; ++a) {
    std::string addr;
    std::string fileName;
    std::string functionName;

    Dl_info dl_info;
    struct link_map *map{};

    // On success, dladdr() return a nonzero value.
    if (0 != dladdr1(stack[a], &dl_info, reinterpret_cast<void **>(&map),
                     RTLD_DL_LINKMAP)) {
      // Convert filename to canonical path
      if (dl_info.dli_fname && dl_info.dli_fname[0] != '\0') {
        char *buf = ::realpath(dl_info.dli_fname, nullptr);
        fileName = buf ? buf : "";
        free(buf);

        // ref:
        // https://code.woboq.org/userspace/glibc/debug/backtracesyms.c.html
        // glibc/debug/backtracesyms.c::62
        dl_info.dli_fbase = reinterpret_cast<void *>(map->l_addr);
      }

      // Make address relative to process start
      addr = internal::addressToString(uint64_t(stack[a]) -
                                       (uint64_t)dl_info.dli_fbase);
      functionName = dl_info.dli_sname ? dl_info.dli_sname : "";
    } else {
      addr = internal::addressToString(uint64_t(stack[a]));
    }

    // Perform demangling if parsed properly
    if (!functionName.empty()) {
      int status = 0;
      auto demangledFunctionName =
          abi::__cxa_demangle(functionName.data(), nullptr, nullptr, &status);
      // if demangling is successful, output the demangled function name
      if (status == 0) {
        // Success (see
        // http://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html)
        functionName = std::string(demangledFunctionName);
      }
      if (demangledFunctionName) {
        free(demangledFunctionName);
      }
    }
    internal::StackTraceEntry entry(a, addr, fileName, functionName, "", -1);
    stackTrace.push_back(entry);
  }

  // Fetch source file & line numbers
  std::map<std::string, std::list<std::string> > fileAddresses;
  std::map<std::string, std::list<std::string> > fileData;
  for (const auto &it : stackTrace) {
    if (it.binary_file_name.length()) {
      if (fileAddresses.find(it.binary_file_name) == fileAddresses.end()) {
        fileAddresses[it.binary_file_name] = {};
      }
      fileAddresses.at(it.binary_file_name).push_back(it.address);
    }
  }
  for (const auto &it : fileAddresses) {
    std::string fileName = it.first;
    std::ostringstream ss;
    ss << "addr2line -C -f -p -e " << fileName << " ";
    for (const auto &it2 : it.second) {
      ss << it2 << " ";
    }
    auto addrLineOutput = internal::SystemToStr(ss.str().c_str());
    if (addrLineOutput.length()) {
      auto outputLines = internal::split(addrLineOutput, '\n');
      fileData[fileName] =
          std::list<std::string>(outputLines.begin(), outputLines.end());
    }
  }
  std::regex addrToLineRegex("^(.+?) at (.+):([0-9]+)");
  for (auto &it : stackTrace) {
    if (it.binary_file_name.length() &&
        fileData.find(it.binary_file_name) != fileData.end()) {
      std::string outputLine = fileData.at(it.binary_file_name).front();
      fileData.at(it.binary_file_name).pop_front();
      if (outputLine == std::string("?? ??:0")) {
        continue;
      }
      std::smatch matches;
      if (regex_search(outputLine, matches, addrToLineRegex)) {
        it.function_name = matches[1];
        it.source_file_name = matches[2];
        it.line_number = std::stoi(matches[3]);
      }
    }
  }

  return StackTrace(stackTrace);
}

}  // namespace stacktrace_dl
