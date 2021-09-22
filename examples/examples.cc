//
// Created by shawnfeng on 2021/9/18.
//

#include <cstdlib>

#include "stacktrace/stacktrace_with_dllib.h"
#include "stacktrace/stacktrace_with_maps.h"

static void func2(void) {
  std::cout << stacktrace::generate();
  std::cout << stacktrace_dl::generate();
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
