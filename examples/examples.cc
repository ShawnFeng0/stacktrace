//
// Created by shawnfeng on 2021/9/18.
//

#include <cstdlib>

#include "stacktrace/stacktrace_with_dladdr.h"
#include "stacktrace/stacktrace_with_maps.h"

static void func2(void) {
  auto frames = StackDump(8);
  for (auto &frame : frames) {
    std::cout << frame.to_string() << std::endl;
  }
  std::cout << stacktrace::generate();
}

void func1(int ncalls) {
  if (ncalls > 1)
    func1(ncalls - 1);
  else
    func2();
}

int main() {
  func1(3);
  exit(EXIT_SUCCESS);
}
