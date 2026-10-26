//! Task 26 parallel isolation for baseline-capture test hooks and counters.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::baseline::capture::test_seams::{
    clear_zip_entry_open_counts, hook_lock, production_blob_map_was_sizes_only,
    set_before_publish_hook, spool_create_attempt_count, spool_name_attempt_count,
    zip_entry_open_count, CaptureHookGuard,
};
use crate::baseline::capture::{
    capture_official_baseline_in_standalone_store, BaselineCaptureOptions, BaselineCaptureRequest,
    IncomingResourceSelector,
};
use crate::baseline::key::SafeResourceKey;
use crate::GkrmError;

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).expect("zip create");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, options).expect("start");
        writer.write_all(bytes).expect("write");
    }
    writer.finish().expect("finish");
}

fn setup_roots(
    temp: &tempfile::TempDir,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let installed = temp.path().join("installed");
    let store = temp.path().join("store");
    let package = temp.path().join("pkg.zip");
    fs::create_dir_all(&installed).unwrap();
    fs::create_dir_all(&store).unwrap();
    fs::write(installed.join("fxmanifest.lua"), b"fx_version 'cerulean'\n").unwrap();
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\nescrow_ignore {\n  'config.lua'\n}\n",
            ),
            ("res/config.lua", b"cfg"),
            ("res/client.lua", b"code"),
        ],
    );
    (installed, store, package)
}

fn capture_once(installed: &Path, store: &Path, package: &Path) -> Result<(), GkrmError> {
    let key = SafeResourceKey::parse("res").unwrap();
    let request = BaselineCaptureRequest::try_new(
        installed,
        store,
        package,
        key,
        IncomingResourceSelector::AutoSingle,
        BaselineCaptureOptions::default(),
    )?;
    let store = crate::resolve_standalone_baseline_store(store)?;
    capture_official_baseline_in_standalone_store(&store, request).map(|_| ())
}

#[test]
fn foreign_capture_does_not_run_owned_before_publish_hook() {
    let barrier = Arc::new(Barrier::new(2));
    let fired = Arc::new(Mutex::new(0u32));

    let owner = {
        let barrier = Arc::clone(&barrier);
        let fired = Arc::clone(&fired);
        thread::spawn(move || {
            let _guard = hook_lock();
            set_before_publish_hook({
                let fired = Arc::clone(&fired);
                move || {
                    *fired.lock().unwrap() += 1;
                    Ok(())
                }
            });
            barrier.wait();
            // Hold ownership while the foreign capture runs, then capture ourselves.
            barrier.wait();
            let temp = tempdir().unwrap();
            let (installed, store, package) = setup_roots(&temp);
            let _ = capture_once(&installed, &store, &package);
        })
    };

    let foreign = {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            let temp = tempdir().unwrap();
            let (installed, store, package) = setup_roots(&temp);
            let _ = capture_once(&installed, &store, &package);
            barrier.wait();
        })
    };

    owner.join().unwrap();
    foreign.join().unwrap();
    assert_eq!(
        *fired.lock().unwrap(),
        1,
        "only the owning thread's capture should run the hook"
    );
}

#[test]
fn two_threads_install_distinct_hooks_without_cross_take() {
    let barrier = Arc::new(Barrier::new(2));
    let a_fired = Arc::new(Mutex::new(0u32));
    let b_fired = Arc::new(Mutex::new(0u32));

    let thread_a = {
        let barrier = Arc::clone(&barrier);
        let a_fired = Arc::clone(&a_fired);
        thread::spawn(move || {
            let _guard = hook_lock();
            set_before_publish_hook({
                let a_fired = Arc::clone(&a_fired);
                move || {
                    *a_fired.lock().unwrap() += 1;
                    Ok(())
                }
            });
            barrier.wait();
            let temp = tempdir().unwrap();
            let (installed, store, package) = setup_roots(&temp);
            let _ = capture_once(&installed, &store, &package);
            barrier.wait();
        })
    };

    let thread_b = {
        let barrier = Arc::clone(&barrier);
        let b_fired = Arc::clone(&b_fired);
        thread::spawn(move || {
            let _guard = hook_lock();
            set_before_publish_hook({
                let b_fired = Arc::clone(&b_fired);
                move || {
                    *b_fired.lock().unwrap() += 1;
                    Ok(())
                }
            });
            barrier.wait();
            let temp = tempdir().unwrap();
            let (installed, store, package) = setup_roots(&temp);
            let _ = capture_once(&installed, &store, &package);
            barrier.wait();
        })
    };

    thread_a.join().unwrap();
    thread_b.join().unwrap();
    assert_eq!(*a_fired.lock().unwrap(), 1);
    assert_eq!(*b_fired.lock().unwrap(), 1);
}

#[test]
fn owned_zip_entry_counter_ignores_foreign_captures() {
    let barrier = Arc::new(Barrier::new(2));
    let owner_counts = Arc::new(Mutex::new(Vec::<u64>::new()));

    let owner = {
        let barrier = Arc::clone(&barrier);
        let owner_counts = Arc::clone(&owner_counts);
        thread::spawn(move || {
            let _guard = hook_lock();
            clear_zip_entry_open_counts();
            barrier.wait();
            // Foreign captures run while we hold ownership.
            barrier.wait();
            let temp = tempdir().unwrap();
            let (installed, store, package) = setup_roots(&temp);
            capture_once(&installed, &store, &package).expect("owner capture");
            let opens: Vec<u64> = (0..16)
                .map(zip_entry_open_count)
                .filter(|c| *c > 0)
                .collect();
            assert!(production_blob_map_was_sizes_only());
            *owner_counts.lock().unwrap() = opens;
        })
    };

    let foreign = {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            for _ in 0..3 {
                let temp = tempdir().unwrap();
                let (installed, store, package) = setup_roots(&temp);
                let _ = capture_once(&installed, &store, &package);
            }
            barrier.wait();
        })
    };

    owner.join().unwrap();
    foreign.join().unwrap();
    let opens = owner_counts.lock().unwrap().clone();
    assert!(!opens.is_empty());
    assert!(
        opens.iter().all(|c| *c == 1),
        "owned counters must stay exact under foreign captures: {opens:?}"
    );
}

#[test]
fn owned_spool_attempt_counters_ignore_foreign_captures() {
    let barrier = Arc::new(Barrier::new(2));
    let snapshot = Arc::new(Mutex::new((0u64, 0u64)));

    let owner = {
        let barrier = Arc::clone(&barrier);
        let snapshot = Arc::clone(&snapshot);
        thread::spawn(move || {
            let _guard = hook_lock();
            barrier.wait();
            barrier.wait();
            let before_create = spool_create_attempt_count();
            let before_name = spool_name_attempt_count();
            let temp = tempdir().unwrap();
            let (installed, store, package) = setup_roots(&temp);
            capture_once(&installed, &store, &package).expect("owner capture");
            *snapshot.lock().unwrap() = (
                spool_create_attempt_count() - before_create,
                spool_name_attempt_count() - before_name,
            );
        })
    };

    let foreign = {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            for _ in 0..3 {
                let temp = tempdir().unwrap();
                let (installed, store, package) = setup_roots(&temp);
                let _ = capture_once(&installed, &store, &package);
            }
            barrier.wait();
        })
    };

    owner.join().unwrap();
    foreign.join().unwrap();
    let (create_delta, name_delta) = *snapshot.lock().unwrap();
    assert!(
        create_delta >= 1,
        "owner should observe its own spool creates"
    );
    assert!(
        name_delta >= 1,
        "owner should observe its own spool name attempts"
    );
}

#[test]
fn panic_inside_hook_restores_state_for_next_test() {
    use std::sync::atomic::{AtomicBool, Ordering};

    {
        let _guard = hook_lock();
        set_before_publish_hook(|| panic!("intentional capture hook panic"));
        let temp = tempdir().unwrap();
        let (installed, store, package) = setup_roots(&temp);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = capture_once(&installed, &store, &package);
        }));
        assert!(result.is_err());
    }

    let _guard = hook_lock();
    let observed = Arc::new(AtomicBool::new(false));
    set_before_publish_hook({
        let observed = Arc::clone(&observed);
        move || {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        }
    });
    let temp = tempdir().unwrap();
    let (installed, store, package) = setup_roots(&temp);
    capture_once(&installed, &store, &package).expect("post-panic capture");
    assert!(
        observed.load(Ordering::SeqCst),
        "new ownership must start clean after panic Drop restore"
    );
}

/// Compile-time proof that `CaptureHookGuard` is not `Send` (thread-local ownership).
fn _capture_hook_guard_is_not_send() {
    trait AmbiguousIfSend<T> {}
    impl<T> AmbiguousIfSend<()> for T {}
    impl<T: Send> AmbiguousIfSend<bool> for T {}
    fn assert_not_send<T: AmbiguousIfSend<()>>() {}
    assert_not_send::<CaptureHookGuard>();
}

#[test]
fn nested_capture_hook_guard_restores_outer_state_exactly() {
    let outer = hook_lock();
    set_before_publish_hook(|| Ok(()));
    clear_zip_entry_open_counts();
    // Seed an outer counter observation by performing one owned capture later; first bump a
    // spool counter indirectly by forcing a name attempt via a nested scope only.
    let temp_outer = tempdir().unwrap();
    let (installed, store, package) = setup_roots(&temp_outer);
    capture_once(&installed, &store, &package).expect("outer capture");
    let outer_opens: Vec<u64> = (0..16)
        .map(zip_entry_open_count)
        .filter(|c| *c > 0)
        .collect();
    assert!(!outer_opens.is_empty());
    let outer_create = spool_create_attempt_count();
    let outer_name = spool_name_attempt_count();
    assert!(production_blob_map_was_sizes_only());

    // Install a distinct inner hook and run an inner capture that consumes it.
    let inner_fired = Arc::new(Mutex::new(0u32));
    {
        let inner = hook_lock();
        set_before_publish_hook({
            let inner_fired = Arc::clone(&inner_fired);
            move || {
                *inner_fired.lock().unwrap() += 1;
                Ok(())
            }
        });
        clear_zip_entry_open_counts();
        let temp_inner = tempdir().unwrap();
        let (installed, store, package) = setup_roots(&temp_inner);
        capture_once(&installed, &store, &package).expect("inner capture");
        let inner_opens: Vec<u64> = (0..16)
            .map(zip_entry_open_count)
            .filter(|c| *c > 0)
            .collect();
        assert!(inner_opens.iter().all(|c| *c == 1));
        assert_eq!(*inner_fired.lock().unwrap(), 1);
        drop(inner);
    }

    // Outer counters and blob-map flag restored; outer before-publish hook was already
    // consumed by the outer capture and must remain absent (not resurrected as inner's).
    assert_eq!(
        (0..16)
            .map(zip_entry_open_count)
            .filter(|c| *c > 0)
            .collect::<Vec<_>>(),
        outer_opens
    );
    assert_eq!(spool_create_attempt_count(), outer_create);
    assert_eq!(spool_name_attempt_count(), outer_name);
    assert!(production_blob_map_was_sizes_only());
    assert_eq!(
        *inner_fired.lock().unwrap(),
        1,
        "inner hook must stay consumed and not fire again after restore"
    );

    drop(outer);

    // Unguarded capture uses production behavior: no owned counters, no hooks.
    let temp = tempdir().unwrap();
    let (installed, store, package) = setup_roots(&temp);
    capture_once(&installed, &store, &package).expect("unguarded");
}

#[test]
fn nested_inner_hook_panic_restores_outer_state() {
    let outer_fired = Arc::new(Mutex::new(0u32));
    let outer = hook_lock();
    set_before_publish_hook({
        let outer_fired = Arc::clone(&outer_fired);
        move || {
            *outer_fired.lock().unwrap() += 1;
            Ok(())
        }
    });

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _inner = hook_lock();
        set_before_publish_hook(|| panic!("inner hook panic"));
        let temp = tempdir().unwrap();
        let (installed, store, package) = setup_roots(&temp);
        let _ = capture_once(&installed, &store, &package);
    }));
    assert!(panicked.is_err());

    // Outer hook still installed and fires exactly once on outer capture.
    let temp = tempdir().unwrap();
    let (installed, store, package) = setup_roots(&temp);
    capture_once(&installed, &store, &package).expect("outer after inner panic");
    assert_eq!(*outer_fired.lock().unwrap(), 1);
    drop(outer);
}

/// Compile-time proof that `WriterCopyHookGuard` is not `Send` / `Sync`.
fn _writer_copy_hook_guard_is_not_send_or_sync() {
    trait AmbiguousIfSend<T> {}
    impl<T> AmbiguousIfSend<()> for T {}
    impl<T: Send> AmbiguousIfSend<bool> for T {}
    fn assert_not_send<T: AmbiguousIfSend<()>>() {}
    assert_not_send::<crate::baseline::capture::test_seams::WriterCopyHookGuard>();

    trait AmbiguousIfSync<T> {}
    impl<T> AmbiguousIfSync<()> for T {}
    impl<T: Sync> AmbiguousIfSync<bool> for T {}
    fn assert_not_sync<T: AmbiguousIfSync<()>>() {}
    assert_not_sync::<crate::baseline::capture::test_seams::WriterCopyHookGuard>();
    assert_not_sync::<CaptureHookGuard>();
}

#[test]
fn nested_writer_copy_hooks_restore_outer_exactly() {
    use crate::baseline::capture::test_seams::{
        set_during_writer_copy_hook, writer_copy_hook_is_armed,
    };

    let outer_fired = Arc::new(Mutex::new(0u32));
    let inner_fired = Arc::new(Mutex::new(0u32));

    let outer = hook_lock();
    let _outer_writer = set_during_writer_copy_hook({
        let outer_fired = Arc::clone(&outer_fired);
        move || {
            *outer_fired.lock().unwrap() += 1;
            Ok(())
        }
    });
    assert!(writer_copy_hook_is_armed());

    {
        let _inner = hook_lock();
        assert!(
            !writer_copy_hook_is_armed(),
            "inner capture guard starts with a fresh writer-hook slot"
        );
        let _inner_writer = set_during_writer_copy_hook({
            let inner_fired = Arc::clone(&inner_fired);
            move || {
                *inner_fired.lock().unwrap() += 1;
                Ok(())
            }
        });
        assert!(writer_copy_hook_is_armed());
        // Consume the inner hook once.
        crate::baseline::capture::test_seams::run_during_writer_copy_hook().unwrap();
        assert_eq!(*inner_fired.lock().unwrap(), 1);
        assert!(!writer_copy_hook_is_armed());
        // Drop order at scope end: writer guard first, then capture guard.
    }

    // Outer writer hook restored exactly; consumed inner is not resurrected.
    assert!(writer_copy_hook_is_armed());
    assert_eq!(*inner_fired.lock().unwrap(), 1);
    assert_eq!(*outer_fired.lock().unwrap(), 0);
    crate::baseline::capture::test_seams::run_during_writer_copy_hook().unwrap();
    assert_eq!(*outer_fired.lock().unwrap(), 1);
    assert!(!writer_copy_hook_is_armed());

    drop(_outer_writer);
    drop(outer);
    assert!(!writer_copy_hook_is_armed());
}

#[test]
fn mixed_capture_and_writer_nested_guards_restore_on_inner_panic() {
    use crate::baseline::capture::test_seams::{
        set_during_writer_copy_hook, writer_copy_hook_is_armed,
    };

    let outer_writer_hits = Arc::new(Mutex::new(0u32));
    let outer = hook_lock();
    let _outer_writer = set_during_writer_copy_hook({
        let outer_writer_hits = Arc::clone(&outer_writer_hits);
        move || {
            *outer_writer_hits.lock().unwrap() += 1;
            Ok(())
        }
    });
    assert!(writer_copy_hook_is_armed());

    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _inner = hook_lock();
        assert!(!writer_copy_hook_is_armed());
        let _inner_writer = set_during_writer_copy_hook(|| panic!("inner writer panic"));
        let _ = crate::baseline::capture::test_seams::run_during_writer_copy_hook();
    }));
    assert!(panicked.is_err());

    assert!(
        writer_copy_hook_is_armed(),
        "outer writer hook must be restored after inner panic unwind"
    );
    assert_eq!(*outer_writer_hits.lock().unwrap(), 0);
    crate::baseline::capture::test_seams::run_during_writer_copy_hook().unwrap();
    assert_eq!(*outer_writer_hits.lock().unwrap(), 1);
    drop(_outer_writer);
    drop(outer);
    assert!(!writer_copy_hook_is_armed());
}

#[test]
fn writer_copy_hook_foreign_thread_isolation() {
    use crate::baseline::capture::test_seams::{
        set_during_writer_copy_hook, writer_copy_hook_is_armed,
    };

    let barrier = Arc::new(Barrier::new(2));
    let owner = {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let _guard = hook_lock();
            let _writer = set_during_writer_copy_hook(|| Ok(()));
            assert!(writer_copy_hook_is_armed());
            barrier.wait();
            barrier.wait();
            assert!(writer_copy_hook_is_armed());
        })
    };
    let foreign = {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            assert!(
                !writer_copy_hook_is_armed(),
                "foreign thread must not observe owner writer hook"
            );
            barrier.wait();
        })
    };
    owner.join().unwrap();
    foreign.join().unwrap();
}

#[test]
fn repeated_parallel_captures_remain_deterministic() {
    for _ in 0..8 {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                thread::spawn(|| {
                    let _guard = hook_lock();
                    clear_zip_entry_open_counts();
                    let temp = tempdir().unwrap();
                    let (installed, store, package) = setup_roots(&temp);
                    capture_once(&installed, &store, &package).expect("parallel capture");
                    let opens: Vec<u64> = (0..16)
                        .map(zip_entry_open_count)
                        .filter(|c| *c > 0)
                        .collect();
                    assert!(!opens.is_empty());
                    assert!(opens.iter().all(|c| *c == 1), "opens={opens:?}");
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("worker");
        }
    }
}
