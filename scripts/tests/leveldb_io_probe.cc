// Standalone snapshot test: no DB, probes, read attribution or live cgroup.
#include "benchmark_snapshots.h"
#include <cassert>
int main(int argc, char** argv) {
  using namespace benchmark;
  assert(argc == 3);
  const char* names[] = {"READ", "UPDATE"};
  uint64_t ops[] = {0, 0};
  Snapshot("Trace", "begin", names, ops, 2); // Disabled.
  assert(OpenSnapshots(argv[1], argv[2]));
  Snapshot("Trace (Warm-Up)", "begin", names, ops, 2);
  ops[0] = 1;
  Snapshot("Trace (Warm-Up)", "end", names, ops, 2);
  ops[0] = 0;
  Snapshot("Trace", "begin", names, ops, 2);
  ops[0] = 4; ops[1] = 2;
  Snapshot("Trace", "end", names, ops, 2);
  Snapshot("Trace", "periodic", names, ops, 2); // Suppressed after end.
  assert(!OpenSnapshots(argv[1], argv[2]));
}
