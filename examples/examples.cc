//
// Created by shawnfeng on 2021/9/18.
//

#include <cstdlib>

#include "stacktrace/stacktrace.h"
#include "stacktrace/ust.h"

static void func2(void) {
  auto frames = StackDump(8);
  for (auto &frame : frames) {
    std::cout << frame.to_string() << std::endl;
  }
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
