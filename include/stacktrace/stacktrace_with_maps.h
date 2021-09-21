#pragma once

#include <cxxabi.h>
#include <execinfo.h>
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
namespace stacktrace {

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

class StackTraceEntry {
 public:
  StackTraceEntry(int _stackIndex, std::string _address,
                  std::string _binaryFileName, std::string _functionName,
                  std::string _sourceFileName, int _lineNumber)
      : stackIndex(_stackIndex),
        address(std::move(_address)),
        binaryFileName(std::move(_binaryFileName)),
        functionName(std::move(_functionName)),
        sourceFileName(std::move(_sourceFileName)),
        lineNumber(_lineNumber) {}

  int stackIndex;
  std::string address;
  std::string binaryFileName;
  std::string functionName;
  std::string sourceFileName;
  int lineNumber;

  friend std::ostream &operator<<(std::ostream &ss, const StackTraceEntry &si);
};

inline std::ostream &operator<<(std::ostream &ss, const StackTraceEntry &si) {
  ss << "#" << si.stackIndex << " " << si.address;
  if (!si.functionName.empty()) {
    ss << " " << si.functionName;
  }
  if (si.lineNumber > 0) {
    std::string sourceFileNameCopy = si.sourceFileName;
    ss << " (" << basename(&sourceFileNameCopy[0]) << ":" << si.lineNumber
       << ")";
  }
  return ss;
}

}  // namespace internal

class StackTrace {
 public:
  explicit StackTrace(std::vector<internal::StackTraceEntry> _entries)
      : entries(std::move(_entries)) {}
  friend std::ostream &operator<<(std::ostream &ss, const StackTrace &si);

  std::vector<internal::StackTraceEntry> entries;
};

inline std::ostream &operator<<(std::ostream &ss, const StackTrace &si) {
  for (const auto &it : si.entries) {
    ss << it << "\n";
  }
  return ss;
}

std::map<std::string, std::pair<uint64_t, uint64_t> > GetAddressMaps() {
  std::map<std::string, std::pair<uint64_t, uint64_t> > addressMaps;
  std::string line;
  std::ifstream infile("/proc/self/maps");
  // Some OSes don't have /proc/*/maps, so we won't have base addresses for them
  while (std::getline(infile, line)) {
    std::istringstream iss(line);
    std::string addressRange;
    std::string perms;
    std::string offset;
    std::string device;
    std::string inode;
    std::string path;

    if (!(iss >> addressRange >> perms >> offset >> device >> inode >> path)) {
      break;
    }  // error
    uint64_t startAddress =
        stoull(internal::split(addressRange, '-')[0], nullptr, 16);
    uint64_t endAddress =
        stoull(internal::split(addressRange, '-')[1], nullptr, 16);
    if (addressMaps.find(path) == addressMaps.end()) {
      addressMaps[path] = std::make_pair(startAddress, endAddress);
    } else {
      addressMaps[path].first = std::min(addressMaps[path].first, startAddress);
      addressMaps[path].second = std::max(addressMaps[path].second, endAddress);
    }
  }
  return addressMaps;
}

// Linux uses backtrace() + addr2line
static const int MAX_STACK_FRAMES = 64;
inline StackTrace generate() {
  // Libunwind and some other functions aren't thread safe.
  static std::mutex mtx;
  static auto addressMaps = GetAddressMaps();

  std::lock_guard<std::mutex> lock(mtx);

  void *stack[MAX_STACK_FRAMES];
  int numFrames = backtrace(stack, MAX_STACK_FRAMES);
  memmove(stack, stack + 1, sizeof(void *) * (numFrames - 1));
  numFrames--;

  char **strings = backtrace_symbols(stack, numFrames);
  std::vector<internal::StackTraceEntry> stackTrace;
  if (strings) {
    for (int a = 0; a < numFrames; ++a) {
      std::string addr;
      std::string fileName;
      std::string functionName;

      const std::string line(strings[a]);

      // Example:
      // ./stacktrace-test(_ZNK5Catch21TestInvokerAsFunction6invokeEv+0x16)
      // [0x55f1278af96e]
      auto parenStart = line.find('(');
      auto parenEnd = line.find(')');
      fileName = line.substr(0, parenStart);
      // Convert filename to canonical path
      char buf[PATH_MAX];
      ::realpath(fileName.c_str(), buf);
      fileName = std::string(buf);
      functionName = line.substr(parenStart + 1, parenEnd - (parenStart + 1));
      // Strip off the offset from the name
      functionName = functionName.substr(0, functionName.find('+'));
      if (addressMaps.find(fileName) != addressMaps.end()) {
        // Make address relative to process start
        addr = internal::addressToString(uint64_t(stack[a]) -
                                         addressMaps[fileName].first);
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
    free(strings);
  }

  // Fetch source file & line numbers
  // Unix & MinGW
  std::map<std::string, std::list<std::string> > fileAddresses;
  std::map<std::string, std::list<std::string> > fileData;
  for (const auto &it : stackTrace) {
    if (it.binaryFileName.length()) {
      if (fileAddresses.find(it.binaryFileName) == fileAddresses.end()) {
        fileAddresses[it.binaryFileName] = {};
      }
      fileAddresses.at(it.binaryFileName).push_back(it.address);
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
    if (it.binaryFileName.length() &&
        fileData.find(it.binaryFileName) != fileData.end()) {
      std::string outputLine = fileData.at(it.binaryFileName).front();
      fileData.at(it.binaryFileName).pop_front();
      if (outputLine == std::string("?? ??:0")) {
        continue;
      }
      std::smatch matches;
      if (regex_search(outputLine, matches, addrToLineRegex)) {
        it.functionName = matches[1];
        it.sourceFileName = matches[2];
        it.lineNumber = std::stoi(matches[3]);
      }
    }
  }

  return StackTrace(stackTrace);
}

}  // namespace stacktrace