"""No probes or benchmark execution: verify retired instrumentation stays absent."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CleanupTest(unittest.TestCase):
    def test_no_leveldb_read_or_compaction_instrumentation(self):
        for relative in ('leveldb/util/env_posix.cc', 'leveldb/db/db_impl.cc',
                         'My-YCSB/leveldb/leveldb_client.cpp'):
            source = (ROOT / relative).read_text()
            for symbol in ('SstReadProbe', 'RecordFileRead', 'ReadSourceScope',
                           'IoCompactionEvent', 'NextIoCompactionId'):
                self.assertNotIn(symbol, source)
        self.assertFalse((ROOT / 'leveldb/util/io_diagnostics.cc').exists())
        self.assertFalse((ROOT / 'leveldb/include/leveldb/io_diagnostics.h').exists())
        # Native LevelDB functionality must not be mistaken for instrumentation.
        source = (ROOT / 'leveldb/db/db_impl.cc').read_text()
        self.assertIn('DBImpl::RecordReadSample', source)
        self.assertIn('DBImpl::DoCompactionWork', source)

    def test_custom_kernel_events_removed_standard_events_retained(self):
        for relative in ('linux/include/trace/events/filemap.h',
                         'linux/mm/filemap.c', 'linux/mm/cache_ext_ds.c'):
            source = (ROOT / relative).read_text()
            for symbol in ('cache_ext_queue_state', 'cache_ext_victim', 'filemap_read_wait'):
                self.assertNotIn(symbol, source)
        self.assertIn('trace_mm_filemap_add_to_page_cache',
                      (ROOT / 'linux/mm/filemap.c').read_text())

    def test_no_runtime_probe_loader(self):
        self.assertFalse((ROOT / 'scripts/leveldb_progress_diagnostics.py').exists())
        for name in ('window_probe', 'window_probe.c', 'probe.bpf.c', 'probe.h'):
            self.assertFalse((ROOT / 'scripts/window_probe' / name).exists())
        source = (ROOT / 'eval/leveldb_io_monitor.sh').read_text()
        self.assertNotIn('PROGRESS_MONITOR', source)
        self.assertNotIn('SST_SAMPLE_EVERY', source)

    def test_lifecycle_counters_and_guards_remain(self):
        source = (ROOT / 'linux/mm/migrate.c').read_text()
        self.assertIn('cache_ext_migration_success_node_present_folios', source)
        source = (ROOT / 'policies/cache_ext_s3fifo.bpf.c').read_text()
        self.assertIn('diag_add_fail_already_linked', source)
        self.assertIn('diag_add_fail_node_invalid', source)


if __name__ == '__main__':
    unittest.main()
