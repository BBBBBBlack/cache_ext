// Small, deterministic tests of the real measurement/worker implementation.
// No database, cgroup, perf, policy attachment, or production trace is used.
#include "worker.h"

#include <cassert>
#include <cmath>
#include <future>
#include <memory>
#include <thread>

using Clock = std::chrono::steady_clock;

static void test_gate_and_uneven_workers() {
  auto m = std::make_unique<OpMeasurement>();
  m->enable_client(0);
  m->enable_client(1);
  m->set_max_progress(3);
  std::promise<void> first_done, allow_last;
  auto first = first_done.get_future().share();
  auto last = allow_last.get_future();
  Clock::time_point last_completion;
  std::thread a([&] {
    m->start_measure();
    m->record_op(READ, 100, 0);
    m->record_progress(1);
    m->finish_measure();
    first_done.set_value();
  });
  std::thread b([&] {
    m->start_measure();
    first.wait();
    // A naturally finished worker must not stop its slower peers.
    assert(!m->finished);
    last.wait();
    m->record_op(READ, 200, 1);
    m->record_op(READ, 300, 1);
    m->record_progress(2);
    last_completion = Clock::now();
    m->finish_measure();
  });
  m->wait_for_clients();
  assert(m->get_op_count(READ) == 0); // Workers are ready but not released.
  m->begin_measure();
  first.wait();
  assert(m->nr_active_client == 1 && !m->finished);
  double throughput[NR_OP_TYPE];
  m->get_rt_throughput(throughput);
  assert(throughput[READ] > 0 && m->rt_previous_op_count[READ] == 1);
  m->get_rt_throughput(throughput);
  assert(throughput[READ] == 0); // Reading stats never resets the op count.
  assert(m->get_op_count(READ) == 1);
  allow_last.set_value();
  a.join();
  b.join();
  assert(m->finished && m->nr_active_client == 0);
  assert(m->end_time >= last_completion && m->end_time > m->start_time);
  assert(m->get_op_count(READ) == 3 && m->cur_progress == 3);
  assert(m->get_latency_average(READ) == 200);
  assert(m->get_latency_percentile(READ, .99f) == 10000);
  assert(m->latency_hist[READ][0] == 3);
  m->get_rt_throughput(throughput);
  assert(throughput[READ] > 0 && m->rt_previous_op_count[READ] == 3);
  double elapsed = std::chrono::duration<double>(m->end_time - m->start_time).count();
  assert(std::abs(m->get_throughput(READ) * elapsed - 3) < 1e-9);
  m->finalize_measure();
}

static void test_timeout_counts_inflight() {
  auto m = std::make_unique<OpMeasurement>();
  m->enable_client(0);
  std::promise<void> entered, complete;
  auto entered_future = entered.get_future();
  auto complete_future = complete.get_future();
  std::thread worker([&] {
    m->start_measure();
    entered.set_value();
    complete_future.wait(); // Operation is in flight at timeout.
    m->record_op(UPDATE, 12345, 0);
    m->finish_measure();
  });
  m->wait_for_clients();
  m->begin_measure();
  entered_future.wait();
  auto stop_time = Clock::now();
  m->finished = true;
  complete.set_value();
  worker.join();
  assert(m->get_op_count(UPDATE) == 1);
  assert(m->get_latency_average(UPDATE) == 12345);
  assert(m->end_time >= stop_time);
  m->finalize_measure();
}

struct FakeClient : Client {
  int calls = 0;
  explicit FakeClient(int id) : Client(id, nullptr) {}
  int do_operation(Operation*) override { ++calls; return 0; }
  int reset() override { return 0; }
  void close() override {}
};

struct StopDuringDecode : Workload {
  OpMeasurement* measurement;
  explicit StopDuringDecode(OpMeasurement* m) : Workload(8, 8), measurement(m) {}
  bool has_next_op() override { return true; }
  void next_op(Operation* op) override {
    op->type = READ;
    measurement->finished = true;
  }
};

static void test_worker_finishes_reserved_op_after_stop() {
  auto m = std::make_unique<OpMeasurement>();
  m->enable_client(0);
  FakeClient client(0);
  StopDuringDecode workload(m.get());
  std::thread worker(worker_thread_fn, &client, &workload, m.get(), 0);
  m->wait_for_clients();
  m->begin_measure();
  worker.join();
  // next_op() has already consumed the entry. Finish/count it rather than
  // silently discarding it between warmup and the measured stage.
  assert(client.calls == 1 && m->get_op_count(READ) == 1);
  assert(m->get_throughput(READ) > 0 && m->get_latency_average(READ) >= 0);
  m->finalize_measure();
}

static void test_real_workers_finish_all_finite_ops() {
  auto m = std::make_unique<OpMeasurement>();
  OpProportion prop{};
  prop.op[READ] = 1;
  UniformWorkload fast(8, 8, 1, 10, 1, prop, 0);
  UniformWorkload slow(8, 8, 1, 10, 13, prop, 1);
  FakeClient a(0), b(1);
  m->enable_client(0);
  m->enable_client(1);
  std::thread ta(worker_thread_fn, &a, &fast, m.get(), 0);
  std::thread tb(worker_thread_fn, &b, &slow, m.get(), 1000000);
  m->wait_for_clients();
  m->begin_measure();
  ta.join();
  tb.join();
  assert(a.calls == 1 && b.calls == 13);
  assert(m->get_op_count(READ) == 14 && m->cur_progress == 14);
  unsigned long samples = 0;
  for (auto& bucket : m->latency_hist[READ]) samples += bucket.load();
  assert(samples == 14);
  m->finalize_measure();
}

int main() {
  test_gate_and_uneven_workers();
  test_timeout_counts_inflight();
  test_worker_finishes_reserved_op_after_stop();
  test_real_workers_finish_all_finite_ops();
  puts("measurement boundary tests passed (4 cases)");
}
