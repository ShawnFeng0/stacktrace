//
// Created by shawnfeng on 2021/11/11.
//

#pragma once

#include <execinfo.h>
#include <stdio.h>

static inline void my_backtrace() {
  constexpr int BT_BUF_SIZE = 100;
  void *stack_raw[BT_BUF_SIZE];
  int num_frames = backtrace(stack_raw, BT_BUF_SIZE);

  // Discard the current stack frame
  void **stack = &stack_raw[1];
  num_frames -= 1;

  printf("backtrace() returned %d addresses\n", num_frames);

  /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
     would produce similar output to the following: */

  char **strings = backtrace_symbols(stack, num_frames);
  if (strings == NULL) {
    perror("backtrace_symbols");
    exit(EXIT_FAILURE);
  }

  for (int j = 0; j < num_frames; j++) printf("%s\n", strings[j]);

  free(strings);
}
