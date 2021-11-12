//
// Created by shawnfeng on 2021/9/18.
//

#include <cstdlib>
#include <iostream>
#include <thread>

#include "backtrace.h"
#include "stacktrace/stacktrace_with_dllib.h"

static void exit_handle(int32_t signal_num) {
  std::cout << "handle signal:" << strsignal(signal_num) << std::endl;
  std::cout << stacktrace_dl::Generate().to_string();
  exit(-1);
}

void crash_point() { *(int*)0x10 = 0; }

void func1() { crash_point(); }

// Same error ref:
// https://www.linuxquestions.org/questions/programming-9/signal-handler-and-pthread-issue-4175418560/
int main() {
  signal(SIGSEGV, exit_handle);
  func1();
}
