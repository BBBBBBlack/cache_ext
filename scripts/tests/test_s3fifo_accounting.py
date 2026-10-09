"""Offline tests: execute policy callbacks with stubs; never load BPF."""
import ast
import contextlib
import logging
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def function(source, name):
    start = source.index(name)
    # Include the return type preceding the name/macro.
    start = source.rfind('\n', 0, start) + 1
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


class AccountingTest(unittest.TestCase):
    def test_callbacks_balance_admission_failures_and_block_unadmitted_debits(self):
        source = (ROOT/'policies/cache_ext_s3fifo.bpf.c').read_text()
        globals_ = '\n'.join(re.findall(
            r'^(?:u64 diag_\w+;|u32 admission_tracking_mask;|s64 (?:small|main)_list_size = 0;)$',
            source, re.M))
        callbacks = '\n'.join(function(source, n) for n in (
            'void BPF_STRUCT_OPS(s3fifo_folio_accessed',
            'void BPF_STRUCT_OPS(s3fifo_folios_evicted',
            'void BPF_STRUCT_OPS(s3fifo_folio_added',
            'static void evict_small('))
        fixture = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;
typedef int64_t s64;
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define BPF_ANY 0
#define CACHE_EXT_ITERATE_SELF 0
#define CACHE_EXT_ITERATE_TAIL 1
#define bpf_printk(...) ((void)0)
struct cache_ext_list_node { u64 metadata[2]; struct { int counter; } state; } node;
struct mapping { void *host; } mapping;
struct folio { struct mapping *mapping; u64 index; } folio = { &mapping, 0 };
struct ghost_entry { u64 address_space, offset; };
struct cache_ext_evicted_ctx { u64 nr_folios; struct folio *folios[32]; };
struct cache_ext_eviction_ctx {};
struct mem_cgroup {};
struct cache_ext_iterate_opts {
 u64 continue_list, continue_mode, evict_list, evict_mode;
 u64 retry_list, retry_mode, deferred_list, deferred_mode, nr_folios_continue;
};
static u64 main_list=1, small_list=2, promotions;
static int ghost_map, missing, fail_add, ghost_hit;
static bool is_folio_relevant(struct folio *f) { return true; }
static bool folio_in_ghost(struct folio *f) { return ghost_hit; }
static void bpf_map_update_elem(void *m, void *k, void *v, int flags) {}
static struct cache_ext_list_node *bpf_cache_ext_folio_to_node(struct folio *f) {
 return missing ? 0 : &node;
}
static int bpf_cache_ext_list_add_tail(u64 list, struct folio *f) {
 if(fail_add) return fail_add;
 node.state.counter |= 16;
 return 0;
}
static int bpf_s3fifo_score_small_fn(int i, struct cache_ext_list_node *n) {return 0;}
static int bpf_cache_ext_list_iterate_extended(struct mem_cgroup *m, u64 list,
 int (*fn)(int, struct cache_ext_list_node*), struct cache_ext_iterate_opts *o,
 struct cache_ext_eviction_ctx *ctx) {o->nr_folios_continue=promotions; return 0;}
'''
        main = r'''
int main(void) {
 /* Only failed accessed lookups count; normal frequency updates are unchanged. */
 missing=1;
 s3fifo_folio_accessed(&folio);
 s3fifo_folio_accessed(&folio);
 assert(diag_accessed_node_missing==2 && node.metadata[0]==0);
 missing=0;
 for (int i=0; i<5; i++) s3fifo_folio_accessed(&folio);
 assert(diag_accessed_node_missing==2 && node.metadata[0]==3);
 struct cache_ext_evicted_ctx e = {.nr_folios=1,.folios={&folio}};
 admission_tracking_mask=16;
 small_list_size=10;
 s3fifo_folios_evicted(&e);
 assert(small_list_size==10);
 node.metadata[1]=1; main_list_size=10;
 s3fifo_folios_evicted(&e);
 assert(main_list_size==10);
 node.state.counter=16; node.metadata[1]=1; main_list_size=10;
 s3fifo_folios_evicted(&e);
 assert(main_list_size==9);
 missing=1; s3fifo_folios_evicted(&e); assert(main_list_size==9); missing=0;
 node.state.counter=0; node.metadata[1]=0; fail_add=-1; small_list_size=0;
 s3fifo_folio_added(&folio);
 assert(small_list_size==0 && diag_add_fail_other==1 && node.state.counter==0);
 s3fifo_folios_evicted(&e);
 assert(small_list_size==0);
 ghost_hit=1; main_list_size=0;
 s3fifo_folio_added(&folio);
 assert(main_list_size==0 && diag_add_fail_other==2 && node.state.counter==0);
 /* Failed duplicate admission must preserve existing metadata and count. */
 node.state.counter=16; node.metadata[1]=1; node.metadata[0]=3;
 main_list_size=1; ghost_hit=0;
 s3fifo_folio_added(&folio);
 assert(small_list_size==0 && main_list_size==1);
 assert(node.state.counter==16 && node.metadata[1]==1 && node.metadata[0]==3);
 s3fifo_folios_evicted(&e); assert(main_list_size==0);
 missing=1; s3fifo_folio_added(&folio); missing=0;
 assert(small_list_size==0 && main_list_size==0 && diag_pre_add_node_missing==1);
 node.state.counter=0; fail_add=0; ghost_hit=0;
 s3fifo_folio_added(&folio);
 assert(small_list_size==1 && node.metadata[1]==0 && node.metadata[0]==0);
 s3fifo_folios_evicted(&e); assert(small_list_size==0);
 fail_add=0; ghost_hit=1; main_list_size=0;
 s3fifo_folio_added(&folio);
 assert(main_list_size==1 && node.metadata[1]==1 && (node.state.counter & 16));
 s3fifo_folios_evicted(&e);
 assert(main_list_size==0);
 /* All failure causes preserve membership metadata and balance sizes. */
 u64 old_other=diag_add_fail_other;
 int errors[] = {-ENOENT, -ESTALE, -EEXIST, -EINVAL};
 node.state.counter=16; node.metadata[0]=3; node.metadata[1]=1;
 for(int ghost=0; ghost<2; ghost++) {
   ghost_hit=ghost;
   for(int i=0; i<4; i++) {
     fail_add=errors[i];
     s3fifo_folio_added(&folio);
     assert(small_list_size==0 && main_list_size==0);
     assert(node.metadata[0]==3 && node.metadata[1]==1 && node.state.counter==16);
   }
 }
 assert(diag_add_fail_list_missing==2 && diag_add_fail_node_invalid==2);
 assert(diag_add_fail_already_linked==2 && diag_add_fail_other==old_other+2);
 assert(diag_add_fail_list_missing+diag_add_fail_node_invalid+
        diag_add_fail_already_linked+diag_add_fail_other == old_other+8);
 small_list_size=10; main_list_size=0; promotions=3;
 evict_small(0,0);
 assert(small_list_size==7 && main_list_size==3);
 assert(diag_small_negative_updates==0 && diag_main_negative_updates==0);
 small_list_size=5; main_list_size=0; promotions=8;
 evict_small(0,0);
 assert(small_list_size==-3 && main_list_size==8);
 assert(diag_small_negative_updates==1);
 promotions=0; evict_small(0,0);
 assert(small_list_size==-3 && diag_small_negative_updates==2);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp)/'callbacks'
            built = subprocess.run(['cc','-x','c','-std=gnu11','-O2','-o',str(binary),'-'],
                           input=fixture+globals_+callbacks+main, text=True,
                           capture_output=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            subprocess.run([str(binary)], check=True)

    def test_fix_keeps_ghost_behavior_and_does_not_clamp_counts(self):
        source = (ROOT/'policies/cache_ext_s3fifo.bpf.c').read_text()
        evicted = function(source, 'void BPF_STRUCT_OPS(s3fifo_folios_evicted')
        self.assertLess(evicted.index('bpf_map_update_elem'), evicted.index('if (!admitted)'))
        transfer = function(source, 'static void evict_small(')
        self.assertNotRegex(transfer, r'(?:small|main)_list_size\s*=(?!=)')
        loader = (ROOT/'policies/cache_ext_s3fifo.c').read_text()
        self.assertIn('revision=6', loader)
        self.assertIn('accessed_node_missing=%llu', loader)
        self.assertEqual(loader.count('SNAP(diag_accessed_node_missing)'), 1)
        self.assertIn('add_fail_total=%llu', loader)
        self.assertNotIn('diag_add_rollback_', source + loader)
        self.assertNotIn('Missing node before add', source)
        for field in ('list_missing', 'node_invalid', 'already_linked', 'other'):
            self.assertEqual(loader.count('SNAP(diag_add_fail_'+field+')'), 1)
        self.assertNotIn('diag_unadmitted_', source)
        self.assertNotIn('Failed to add folio to list', source)
        self.assertNotIn('reset_stores', loader)

    def test_reclaim_has_no_duplicate_printk_totals(self):
        source = (ROOT/'linux/mm/vmscan.c').read_text()
        reclaim = function(source, 'static noinline unsigned long __cache_ext_isolate_and_reclaim(')
        for obsolete in ('total_requested', 'total_returned', 'nr_batches',
                         'nr_invalid', 'nr_isolate_fail', 'pr_info_ratelimited'):
            self.assertNotIn(obsolete, reclaim)
        for kept in ('requested_pages', 'returned_folios', 'returned_pages',
                     'submitted_folios', 'submitted_pages'):
            self.assertIn('CACHE_EXT_RECLAIM_'+kept, reclaim)
        self.assertIn('cache_ext_list_node_unpin(pinned_node)', reclaim)
        self.assertNotIn('cache_ext_isolate_folios(', source)
        isolate = function(source, 'static bool cache_ext_isolate_folio(')
        self.assertIn('folio_lruvec_lock_irq(folio)', isolate)
        self.assertIn('unlock_page_lruvec_irq(lruvec)', isolate)
        self.assertIn('wakeup_flusher_threads', reclaim)

    def test_marker_is_only_set_after_successful_locked_admission(self):
        ds = (ROOT/'linux/mm/cache_ext_ds.c').read_text()
        add = function(ds, 'int __cache_ext_list_add_impl(')
        marker = add.index('atomic_or(CACHE_EXT_NODE_EVER_ADMITTED')
        self.assertLess(add.index('list_add_tail('), marker)
        self.assertLess(add.index('cache_ext_ds_registry_write_lock('), marker)
        self.assertLess(marker, add.rindex('cache_ext_ds_registry_write_unlock('))
        self.assertIn('BTF_ID_FLAGS(func, bpf_cache_ext_admission_tracking_mask)', ds)
        policy = (ROOT/'policies/cache_ext_s3fifo.bpf.c').read_text()
        accessed = function(policy, 'void BPF_STRUCT_OPS(s3fifo_folio_accessed')
        self.assertNotIn('bpf_printk', accessed)
        failure = function(accessed, 'if (!node)')
        self.assertIn('__sync_fetch_and_add(&diag_accessed_node_missing, 1)', failure)
        self.assertNotIn('diag_', accessed.replace(failure, ''))

    def test_kernel_errors_and_migration_observer_are_non_mutating(self):
        ds = (ROOT/'linux/mm/cache_ext_ds.c').read_text()
        add = function(ds, 'int __cache_ext_list_add_impl(')
        self.assertIn('return -EINVAL;', add)
        self.assertIn('return -ESTALE;', add)
        self.assertIn('return -EEXIST;', add)
        self.assertNotIn('return -1;', add)
        for name in ('bpf_cache_ext_list_add(', 'bpf_cache_ext_list_add_tail('):
            wrapper = function(ds, '__bpf_kfunc int '+name)
            self.assertIn('cache_ext_ds_registry_get(', wrapper)
            self.assertIn('return -EINVAL;', wrapper)
            self.assertIn('return -ENOENT;', wrapper)
        source = (ROOT/'linux/mm/migrate.c').read_text()
        move = function(source, 'static int move_to_new_folio(')
        counter = 'cache_ext_migration_success_node_present_folios'
        self.assertEqual(source.count(counter), 1)
        self.assertLess(move.index('if (rc == MIGRATEPAGE_SUCCESS)'), move.index(counter))
        self.assertLess(move.index(counter), move.index('src->mapping = NULL'))
        diag = move[move.index('#ifdef CONFIG_MEMCG'):move.index('#endif')]
        self.assertIn('READ_ONCE(src->cache_ext_node)', diag)
        self.assertIn('memcg && memcg->cache_ext_valid', diag)
        self.assertNotIn('node->', diag)
        self.assertNotIn('WRITE_ONCE', diag)
        self.assertNotIn('list_', diag)
        header = (ROOT/'linux/include/linux/cache_ext.h').read_text()
        self.assertNotIn('X(migration_success_node_present_folios)', header)

    def test_loader_output_larger_than_a_pipe_does_not_block(self):
        tree = ast.parse((ROOT/'bench/bench_lib.py').read_text())
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name=='CacheExtPolicy')
        ns = dict(tempfile=tempfile, subprocess=subprocess, sleep=lambda _: None,
                  suppress=contextlib.suppress, log=logging.getLogger('test-policy'))
        exec(compile(ast.Module(body=[cls], type_ignores=[]), 'bench_lib.py', 'exec'), ns)
        policy = ns['CacheExtPolicy']('test','unused','unused')
        real_popen = subprocess.Popen
        def launch(*args, **kwargs):
            return real_popen(['python3','-c',
                'import sys; sys.stdout.write("x"*200000); sys.stderr.write("y"*200000)'], **kwargs)
        with patch.object(subprocess, 'Popen', side_effect=launch):
            policy.start()
        policy._policy_thread.wait(timeout=5)
        ns['run'] = lambda _: None
        with self.assertLogs('test-policy', level='INFO') as logs:
            policy.stop()
        self.assertIn('x'*200000, '\n'.join(logs.output))
        self.assertIn('y'*200000, '\n'.join(logs.output))
        self.assertIsNone(policy._policy_stdout)
        self.assertFalse(policy.has_started)


if __name__ == '__main__':
    unittest.main()
