#pragma once

#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>

#include <iostream>
#include <sstream>
#include <utility>
#include <vector>

class StackFrame {
 public:
  StackFrame(const char *filename, void *file_base_address,
             void *relative_address, std::string symbol_name,
             void *symbol_address)
      : filename(filename),
        file_base_address(file_base_address),
        stack_address(relative_address),
        symbol_name(std::move(symbol_name)),
        symbol_address(symbol_address) {}

  std::string to_string() const {
    std::string ret{filename};
    std::stringstream relative_address_str;
    relative_address_str << (void *)((uintptr_t)stack_address -
                                     (uintptr_t)file_base_address);
    ret += "(" + relative_address_str.str() + ")";
    ret += " " + symbol_name;
    return ret;
  }

  const char *filename;     // File name of defining object.
  void *file_base_address;  // Load address of that object.
  void *stack_address;      // File name of defining object.
  std::string symbol_name;  // Name of nearest symbol.
  void *symbol_address;     // Exact value of nearest symbol.
};

static inline std::vector<StackFrame> StackDump(size_t depth) {
  std::vector<void *> address_buffer;
  address_buffer.resize(depth);

  int count = backtrace(address_buffer.data(), (int)address_buffer.size());

  std::vector<StackFrame> frames;

  Dl_info info;
  for (int i = 0; i < count; i++) {
    // https://github.com/wayland-project/weston/blob/1.9/src/main.c#L142:1
    dladdr(address_buffer[i], &info);
    std::string symbol_name;
    if (info.dli_sname) {
      int ok;
      char *demangled =
          abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &ok);
      if (demangled) {
        symbol_name = demangled;
        free(demangled);
      }
    }

    frames.emplace_back(info.dli_fname, info.dli_fbase, address_buffer[i],
                        symbol_name, info.dli_saddr);
  }
  return frames;
}
