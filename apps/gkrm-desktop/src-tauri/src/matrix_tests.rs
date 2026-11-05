//! Every combination of what the operator, the developer and the last install did to a file.
//!
//! Each scenario is one resource. Its two files — one the operator may edit, one escrow protects —
//! start from what was installed, then the developer ships a new version and the operator may have
//! changed theirs. The five relations between those three versions are crossed for both files,
//! with and without the package the resource was last installed from, with and without a file the
//! developer added, and with and without a file only the operator has.
//!
//! What the plan should say is worked out here by an oracle that does not look at the product's
//! code: it is the documented rule, written down again. The product has to agree with it, and
//! then keep every promise around it — planning writes nothing, only what needed no answer is
//! written, everything else is byte for byte what it was, an update can be put back exactly, and
//! asking again afterwards does not find more to do.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    resolve_trusted_update_workspace, retire_trusted_terminal_update_evidence,
    TrustedTerminalEvidenceRetirementOptions,
};

use crate::batch::{batch_apply, batch_plan, batch_release};
use crate::dto::{BatchApplyResultKind, BatchEntryKind, SelectionKind};
use crate::state::DesktopAppState;

const MANIFEST: &[u8] =
    b"fx_version 'cerulean'\nversion '1.0.0'\nescrow_ignore { 'config.lua' }\nclient_script 'client.lua'\n";

type Tree = BTreeMap<String, Vec<u8>>;

/// How the three versions of one file relate: what was installed from, what the developer ships
/// now, and what the operator has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Relation {
    /// Nobody changed it.
    Equal,
    /// Only the developer changed it.
    DevChanged,
    /// Only the operator changed it.
    OperatorOnly,
    /// Both changed it to the same thing.
    Converged,
    /// Both changed it, to different things.
    Conflict,
}

const RELATIONS: [Relation; 5] = [
    Relation::Equal,
    Relation::DevChanged,
    Relation::OperatorOnly,
    Relation::Converged,
    Relation::Conflict,
];

/// `(installed from, developer ships, operator has)` for one file.
fn versions(relation: Relation, label: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let one = format!("{label} = 1\n").into_bytes();
    let two = format!("{label} = 2\n").into_bytes();
    let three = format!("{label} = 3\n").into_bytes();
    match relation {
        Relation::Equal => (one.clone(), one.clone(), one),
        Relation::DevChanged => (one.clone(), two, one),
        Relation::OperatorOnly => (one.clone(), one, three),
        Relation::Converged => (one, two.clone(), two),
        Relation::Conflict => (one, two, three),
    }
}

#[derive(Clone, Debug)]
struct Scenario {
    name: String,
    editable: Relation,
    protected: Relation,
    /// Whether the package the resource was last installed from is on record.
    remembered: bool,
    /// Whether the developer added a file.
    developer_file: bool,
    /// Whether the operator has a file the package does not.
    operator_file: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Expect {
    Ready,
    NeedsReview,
    UpToDate,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Action {
    Unchanged,
    Take,
    Review,
    KeepYours,
}

/// The documented rule, written down again and independent of the plan's own code.
fn editable_action(s: &Scenario) -> Action {
    let (base, incoming, local) = versions(s.editable, "Config.A");
    if local == incoming {
        Action::Unchanged
    } else if s.remembered && incoming == base {
        // The developer shipped exactly what was installed, so the difference is the operator's.
        Action::KeepYours
    } else if s.remembered && local == base {
        // Only the developer changed it.
        Action::Take
    } else {
        Action::Review
    }
}

/// A protected file is the developer's whatever the operator did to it.
fn protected_action(s: &Scenario) -> Action {
    let (_, incoming, local) = versions(s.protected, "client");
    if local == incoming {
        Action::Unchanged
    } else {
        Action::Take
    }
}

fn expectation(s: &Scenario) -> Expect {
    let actions = [editable_action(s), protected_action(s)];
    let reviews = actions.iter().filter(|a| **a == Action::Review).count();
    let takes =
        actions.iter().filter(|a| **a == Action::Take).count() + usize::from(s.developer_file);
    if reviews > 0 {
        Expect::NeedsReview
    } else if takes > 0 {
        Expect::Ready
    } else {
        Expect::UpToDate
    }
}

fn scenarios() -> Vec<Scenario> {
    let mut all = Vec::new();
    for editable in RELATIONS {
        for protected in RELATIONS {
            for remembered in [false, true] {
                for developer_file in [false, true] {
                    for operator_file in [false, true] {
                        all.push(Scenario {
                            name: format!("res-{:03}", all.len()),
                            editable,
                            protected,
                            remembered,
                            developer_file,
                            operator_file,
                        });
                    }
                }
            }
        }
    }
    all
}

fn write_zip(path: &Path, entries: &[(String, Vec<u8>)]) {
    let file = fs::File::create(path).expect("zip");
    let mut writer = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, contents) in entries {
        writer.start_file(name.as_str(), options).expect("entry");
        writer.write_all(contents).expect("bytes");
    }
    writer.finish().expect("finish");
}

fn write_tree(root: &Path, files: &[(&str, Vec<u8>)]) {
    for (relative, contents) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        fs::write(path, contents).expect("write");
    }
}

fn snapshot(dir: &Path) -> Tree {
    fn walk(root: &Path, here: &Path, out: &mut Tree) {
        let Ok(entries) = fs::read_dir(here) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("relative")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(relative, fs::read(&path).expect("bytes"));
            }
        }
    }
    let mut out = Tree::new();
    walk(dir, dir, &mut out);
    out
}

fn select(state: &DesktopAppState, kind: SelectionKind, path: &Path) -> String {
    let mut generator = crate::selection::UuidHandleGenerator;
    state
        .selections
        .lock()
        .expect("selections")
        .insert(kind, path.to_path_buf(), &mut generator)
        .expect("selection")
        .handle
}

fn release(state: &DesktopAppState, handle: &str) {
    let _ = state.selections.lock().expect("selections").release(handle);
}

fn close_finished_updates(app_data: &Path) {
    let workspace = resolve_trusted_update_workspace(app_data).expect("workspace");
    let _ = retire_trusted_terminal_update_evidence(
        &workspace,
        TrustedTerminalEvidenceRetirementOptions {
            acknowledged: true,
            ..Default::default()
        },
    );
}

struct World {
    _temp: tempfile::TempDir,
    installed: PathBuf,
    packages: PathBuf,
    app_data: PathBuf,
    state: DesktopAppState,
    installed_handle: String,
    packages_handle: String,
}

/// An installation and a folder of packages for every scenario in the chunk.
fn build_world(chunk: &[Scenario]) -> World {
    let temp = tempfile::tempdir().expect("temp");
    let installed = temp.path().join("resources");
    let packages = temp.path().join("packages");
    let baselines = temp.path().join("baselines");
    let app_data = temp.path().join("app-data");
    for dir in [&installed, &packages, &baselines, &app_data] {
        fs::create_dir_all(dir).expect("dir");
    }
    let state = DesktopAppState::default();
    let installed_handle = select(&state, SelectionKind::InstalledRoot, &installed);
    let packages_handle = select(&state, SelectionKind::PackagesFolder, &packages);

    for s in chunk {
        let (e_base, e_in, e_local) = versions(s.editable, "Config.A");
        let (p_base, p_in, p_local) = versions(s.protected, "client");
        let resource = installed.join(&s.name);

        if s.remembered {
            // Installed from a package, which the app kept — the way it happens for real.
            write_tree(
                &resource,
                &[
                    ("fxmanifest.lua", MANIFEST.to_vec()),
                    ("config.lua", b"Config.A = 0\n".to_vec()),
                    ("client.lua", b"client = 0\n".to_vec()),
                ],
            );
            let base_zip = baselines.join(format!("{}.zip", s.name));
            write_zip(
                &base_zip,
                &[
                    (format!("{}/fxmanifest.lua", s.name), MANIFEST.to_vec()),
                    (format!("{}/config.lua", s.name), e_base.clone()),
                    (format!("{}/client.lua", s.name), p_base.clone()),
                ],
            );
            let package_handle = select(&state, SelectionKind::PackageFile, &base_zip);
            let preview = crate::update::two_way_preview(
                &state,
                &installed_handle,
                &package_handle,
                None,
                app_data.clone(),
            )
            .unwrap_or_else(|f| panic!("{}: install preview failed: {f:?}", s.name));
            let applied = crate::update::two_way_apply(&state, &preview.handle, false, &[])
                .unwrap_or_else(|f| panic!("{}: install apply failed: {f:?}", s.name));
            assert_eq!(applied.outcome, "committed", "{}: install", s.name);
            release(&state, &package_handle);
            crate::update::two_way_release(&state, &preview.handle).expect("release");
            assert_eq!(
                fs::read(resource.join("config.lua")).expect("config"),
                e_base,
                "{}: installed exactly what the baseline ships",
                s.name
            );
        }

        // What the operator has now.
        let mut local: Vec<(&str, Vec<u8>)> = vec![
            ("fxmanifest.lua", MANIFEST.to_vec()),
            ("config.lua", e_local),
            ("client.lua", p_local),
        ];
        if s.operator_file {
            local.push(("data/notes.txt", b"mine\n".to_vec()));
        }
        write_tree(&resource, &local);

        // What the developer ships.
        let mut incoming = vec![
            (format!("{}/fxmanifest.lua", s.name), MANIFEST.to_vec()),
            (format!("{}/config.lua", s.name), e_in),
            (format!("{}/client.lua", s.name), p_in),
        ];
        if s.developer_file {
            incoming.push((format!("{}/client/new.lua", s.name), b"new\n".to_vec()));
        }
        write_zip(&packages.join(format!("{}.zip", s.name)), &incoming);
    }
    close_finished_updates(&app_data);

    World {
        _temp: temp,
        installed,
        packages,
        app_data,
        state,
        installed_handle,
        packages_handle,
    }
}

fn kind_of(expect: Expect) -> BatchEntryKind {
    match expect {
        Expect::Ready => BatchEntryKind::Ready,
        Expect::NeedsReview => BatchEntryKind::NeedsReview,
        Expect::UpToDate => BatchEntryKind::UpToDate,
    }
}

fn plan_kinds(world: &World, chunk: &[Scenario]) -> BTreeMap<String, BatchEntryKind> {
    let plan = batch_plan(
        &world.state,
        &world.installed_handle,
        &world.packages_handle,
        world.app_data.clone(),
    )
    .expect("plan");
    batch_release(&world.state, &plan.handle).expect("release");
    assert_eq!(plan.entries.len(), chunk.len(), "one entry per package");
    plan.entries
        .iter()
        .map(|entry| (entry.resource.clone().expect("resource"), entry.kind))
        .collect()
}

/// What the files of a resource should be after it was updated without being asked anything.
fn expected_after_update(s: &Scenario, before: &Tree) -> Tree {
    let mut tree = before.clone();
    let (_, p_in, _) = versions(s.protected, "client");
    let (_, e_in, _) = versions(s.editable, "Config.A");
    tree.insert("client.lua".into(), p_in);
    if editable_action(s) == Action::Take {
        tree.insert("config.lua".into(), e_in);
    }
    if s.developer_file {
        tree.insert("client/new.lua".into(), b"new\n".to_vec());
    }
    tree
}

/// Run one chunk of scenarios through plan, apply, ask again, put back, ask again.
///
/// Returns what each updated resource looked like afterwards, so another flow can be held to the
/// same result.
fn run_chunk(chunk: &[Scenario]) -> BTreeMap<String, Tree> {
    let world = build_world(chunk);
    let before_all: BTreeMap<String, Tree> = chunk
        .iter()
        .map(|s| (s.name.clone(), snapshot(&world.installed.join(&s.name))))
        .collect();

    // 1. What the plan says is what the rule says, and saying it writes nothing.
    let planned = plan_kinds(&world, chunk);
    for s in chunk {
        assert_eq!(
            planned[&s.name],
            kind_of(expectation(s)),
            "{}: plan for {s:?}",
            s.name
        );
        assert_eq!(
            snapshot(&world.installed.join(&s.name)),
            before_all[&s.name],
            "{}: planning wrote something",
            s.name
        );
    }

    // 2. Applying writes exactly what needed no answer and leaves everything else as it was.
    let undo_before: Vec<String> = crate::undo::list(&world.app_data)
        .into_iter()
        .map(|record| record.id)
        .collect();
    let plan = batch_plan(
        &world.state,
        &world.installed_handle,
        &world.packages_handle,
        world.app_data.clone(),
    )
    .expect("plan");
    let applied = batch_apply(&world.state, &plan.handle).expect("apply");
    let ready = chunk
        .iter()
        .filter(|s| expectation(s) == Expect::Ready)
        .count();
    assert_eq!(applied.committed_count as usize, ready, "committed count");
    let mut after_all = BTreeMap::new();
    for entry in &plan.entries {
        let name = entry.resource.clone().expect("resource");
        let s = chunk.iter().find(|s| s.name == name).expect("scenario");
        let result = applied
            .results
            .iter()
            .find(|result| result.id == entry.id)
            .expect("result")
            .result;
        let now = snapshot(&world.installed.join(&name));
        if expectation(s) == Expect::Ready {
            assert_eq!(result, BatchApplyResultKind::Committed, "{name}: result");
            assert_eq!(
                now,
                expected_after_update(s, &before_all[&name]),
                "{name}: files after the update for {s:?}"
            );
            after_all.insert(name.clone(), now);
        } else {
            assert_eq!(result, BatchApplyResultKind::Skipped, "{name}: result");
            assert_eq!(
                now, before_all[&name],
                "{name}: was touched without being asked"
            );
        }
    }
    let _ = batch_release(&world.state, &plan.handle);
    close_finished_updates(&world.app_data);

    // 3. Asking again finds nothing more to do for what was updated, and the same for the rest.
    let again = plan_kinds(&world, chunk);
    for s in chunk {
        let expected = if expectation(s) == Expect::Ready {
            BatchEntryKind::UpToDate
        } else {
            kind_of(expectation(s))
        };
        assert_eq!(again[&s.name], expected, "{}: asked again", s.name);
    }

    // 4. Each update can be put back exactly, and then it is offered again as it was.
    let workspace = resolve_trusted_update_workspace(&world.app_data).expect("workspace");
    let new_records: Vec<_> = crate::undo::list(&world.app_data)
        .into_iter()
        .filter(|record| !undo_before.contains(&record.id))
        .collect();
    assert_eq!(new_records.len(), ready, "one undo record per update");
    for record in &new_records {
        crate::undo::undo(&workspace, record)
            .unwrap_or_else(|f| panic!("{}: undo failed: {f:?}", record.resource));
        assert_eq!(
            snapshot(&world.installed.join(&record.resource)),
            before_all[&record.resource],
            "{}: put back byte for byte",
            record.resource
        );
    }
    close_finished_updates(&world.app_data);
    let restored = plan_kinds(&world, chunk);
    for s in chunk {
        assert_eq!(
            restored[&s.name],
            kind_of(expectation(s)),
            "{}: offered again as before after undo",
            s.name
        );
    }
    after_all
}

/// The same updates, one resource at a time through the single-resource screen's code.
fn run_single_flow(chunk: &[Scenario]) -> BTreeMap<String, Tree> {
    let world = build_world(chunk);
    let mut after_all = BTreeMap::new();
    for s in chunk {
        let package = world.packages.join(format!("{}.zip", s.name));
        let handle = select(&world.state, SelectionKind::PackageFile, &package);
        let preview = crate::update::two_way_preview(
            &world.state,
            &world.installed_handle,
            &handle,
            None,
            world.app_data.clone(),
        )
        .unwrap_or_else(|f| panic!("{}: preview failed: {f:?}", s.name));
        let asked = preview.summary.review;
        assert_eq!(
            asked > 0,
            expectation(s) == Expect::NeedsReview,
            "{}: the single screen asks exactly when the batch would",
            s.name
        );
        if expectation(s) == Expect::Ready {
            let applied = crate::update::two_way_apply(&world.state, &preview.handle, true, &[])
                .unwrap_or_else(|f| panic!("{}: apply failed: {f:?}", s.name));
            assert_eq!(applied.outcome, "committed", "{}", s.name);
            after_all.insert(s.name.clone(), snapshot(&world.installed.join(&s.name)));
        }
        crate::update::two_way_release(&world.state, &preview.handle).expect("release");
        release(&world.state, &handle);
    }
    after_all
}

/// Small enough that the workspace's own limits never come into it.
const CHUNK: usize = 25;

/// One scenario for every pair of relations, with the other three choices varied across them.
///
/// Fast enough to run with everything else, and still puts every way the two files can relate
/// through the whole sequence. The full set below is the one to run before a release.
fn sample() -> Vec<Scenario> {
    let mut chosen = Vec::new();
    for (index, (editable, protected)) in RELATIONS
        .iter()
        .flat_map(|e| RELATIONS.iter().map(move |p| (*e, *p)))
        .enumerate()
    {
        chosen.push(Scenario {
            name: format!("res-{index:03}"),
            editable,
            protected,
            remembered: index % 2 == 0,
            developer_file: index % 3 == 0,
            operator_file: index % 4 < 2,
        });
    }
    chosen
}

#[test]
fn a_sample_of_every_pair_of_relations_plans_applies_and_puts_back_as_the_rule_says() {
    let chosen = sample();
    assert_eq!(chosen.len(), 25);
    for expect in [Expect::Ready, Expect::NeedsReview, Expect::UpToDate] {
        assert!(
            chosen.iter().any(|s| expectation(s) == expect),
            "{expect:?} is covered"
        );
    }
    // Both with and without the package it was installed from.
    assert!(chosen.iter().any(|s| s.remembered) && chosen.iter().any(|s| !s.remembered));
    run_chunk(&chosen);
}

#[test]
fn a_sample_of_the_batch_and_the_single_screen_write_the_same_files() {
    let chosen = sample();
    let batch = run_chunk(&chosen);
    let single = run_single_flow(&chosen);
    assert_eq!(
        batch.keys().collect::<Vec<_>>(),
        single.keys().collect::<Vec<_>>()
    );
    for (name, tree) in &batch {
        assert_eq!(
            tree, &single[name],
            "{name}: both flows wrote the same files"
        );
    }
}

/// All 200 scenarios. Every update is written durably, so this takes about twenty minutes:
///
/// `cargo test -p gkrm-desktop every_combination -- --ignored`
#[test]
#[ignore = "about twenty minutes; run before a release"]
fn every_combination_plans_applies_and_puts_back_as_the_rule_says() {
    let all = scenarios();
    assert_eq!(all.len(), 200);
    // Both outcomes the batch writes and the ones it must not are really in the set.
    for expect in [Expect::Ready, Expect::NeedsReview, Expect::UpToDate] {
        assert!(
            all.iter().filter(|s| expectation(s) == expect).count() >= 10,
            "{expect:?} is covered"
        );
    }
    for chunk in all.chunks(CHUNK) {
        run_chunk(chunk);
    }
}

#[test]
#[ignore = "about twenty minutes; run before a release"]
fn the_batch_and_the_single_screen_write_the_same_files() {
    for chunk in scenarios().chunks(CHUNK) {
        let batch = run_chunk(chunk);
        let single = run_single_flow(chunk);
        assert_eq!(
            batch.keys().collect::<Vec<_>>(),
            single.keys().collect::<Vec<_>>(),
            "the same resources were updated"
        );
        for (name, tree) in &batch {
            assert_eq!(
                tree, &single[name],
                "{name}: both flows wrote the same files"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Awkward folders and awkward sequences.
// ---------------------------------------------------------------------------------------------

/// Two resources the developer has a plain update for, and a world to put them in.
fn two_ready(names: [&str; 2]) -> World {
    let temp = tempfile::tempdir().expect("temp");
    let installed = temp.path().join("resources");
    let packages = temp.path().join("packages");
    let app_data = temp.path().join("app-data");
    for dir in [&installed, &packages, &app_data] {
        fs::create_dir_all(dir).expect("dir");
    }
    for name in names {
        write_tree(
            &installed.join(name),
            &[
                ("fxmanifest.lua", MANIFEST.to_vec()),
                ("config.lua", b"Config.A = 1\n".to_vec()),
                ("client.lua", b"client = 1\n".to_vec()),
            ],
        );
        write_zip(
            &packages.join(format!("{name}.zip")),
            &[
                (format!("{name}/fxmanifest.lua"), MANIFEST.to_vec()),
                (format!("{name}/config.lua"), b"Config.A = 1\n".to_vec()),
                (format!("{name}/client.lua"), b"client = 2\n".to_vec()),
            ],
        );
    }
    let state = DesktopAppState::default();
    let installed_handle = select(&state, SelectionKind::InstalledRoot, &installed);
    let packages_handle = select(&state, SelectionKind::PackagesFolder, &packages);
    World {
        _temp: temp,
        installed,
        packages,
        app_data,
        state,
        installed_handle,
        packages_handle,
    }
}

fn plan(world: &World) -> crate::dto::BatchPlanResponse {
    batch_plan(
        &world.state,
        &world.installed_handle,
        &world.packages_handle,
        world.app_data.clone(),
    )
    .expect("plan")
}

fn kind_for(plan: &crate::dto::BatchPlanResponse, package: &str) -> BatchEntryKind {
    plan.entries
        .iter()
        .find(|entry| entry.package_name == package)
        .unwrap_or_else(|| panic!("no entry for {package}"))
        .kind
}

#[test]
fn a_folder_with_everything_odd_in_it_is_planned_without_harm() {
    let world = two_ready(["alpha", "beta"]);
    let packages = &world.packages;

    // A package for a resource that is not installed.
    write_zip(
        &packages.join("gamma.zip"),
        &[("gamma/fxmanifest.lua".into(), MANIFEST.to_vec())],
    );
    // Two packages for one installed resource: neither may be chosen.
    write_tree(
        &world.installed.join("delta"),
        &[
            ("fxmanifest.lua", MANIFEST.to_vec()),
            ("client.lua", b"1\n".to_vec()),
        ],
    );
    for name in ["delta-one.zip", "delta-two.zip"] {
        write_zip(
            &packages.join(name),
            &[
                ("delta/fxmanifest.lua".into(), MANIFEST.to_vec()),
                ("delta/client.lua".into(), b"2\n".to_vec()),
            ],
        );
    }
    // Not zips at all, or not readable ones.
    fs::write(packages.join("corrupt.zip"), b"this is not a zip file").expect("corrupt");
    fs::write(packages.join("empty.zip"), b"").expect("empty");
    // Two resources in one package.
    write_zip(
        &packages.join("two.zip"),
        &[
            ("one/fxmanifest.lua".into(), MANIFEST.to_vec()),
            ("two/fxmanifest.lua".into(), MANIFEST.to_vec()),
        ],
    );
    // A package with no resource in it.
    write_zip(
        &packages.join("nothing.zip"),
        &[("readme.txt".into(), b"hello".to_vec())],
    );
    // A package that tries to write outside the installation.
    write_zip(
        &packages.join("escape.zip"),
        &[
            ("alpha/fxmanifest.lua".into(), MANIFEST.to_vec()),
            ("../escaped.lua".into(), b"gotcha".to_vec()),
        ],
    );
    // Things in the folder that are not packages, or not in the folder.
    fs::write(packages.join("notes.txt"), b"x").expect("notes");
    fs::create_dir_all(packages.join("folder.zip")).expect("directory named like a zip");
    fs::create_dir_all(packages.join("nested")).expect("nested");
    write_zip(
        &packages.join("nested/hidden.zip"),
        &[("hidden/fxmanifest.lua".into(), MANIFEST.to_vec())],
    );
    // The extension in capitals is still a zip.
    fs::copy(packages.join("beta.zip"), packages.join("UPPER.ZIP")).expect("upper");
    fs::remove_file(packages.join("beta.zip")).expect("rename");

    let outside = world
        .installed
        .parent()
        .expect("parent")
        .join("escaped.lua");
    let before = snapshot(&world.installed);
    let planned = plan(&world);

    assert_eq!(
        kind_for(&planned, "gamma.zip"),
        BatchEntryKind::NoInstalledResource
    );
    assert_eq!(
        kind_for(&planned, "delta-one.zip"),
        BatchEntryKind::DuplicatePackage
    );
    assert_eq!(
        kind_for(&planned, "delta-two.zip"),
        BatchEntryKind::DuplicatePackage
    );
    assert_eq!(
        kind_for(&planned, "corrupt.zip"),
        BatchEntryKind::Unreadable
    );
    assert_eq!(kind_for(&planned, "empty.zip"), BatchEntryKind::Unreadable);
    assert_eq!(
        kind_for(&planned, "two.zip"),
        BatchEntryKind::NotASingleResource
    );
    assert_eq!(
        kind_for(&planned, "nothing.zip"),
        BatchEntryKind::NotASingleResource
    );
    assert_ne!(kind_for(&planned, "escape.zip"), BatchEntryKind::Ready);
    assert_eq!(kind_for(&planned, "alpha.zip"), BatchEntryKind::Ready);
    assert_eq!(kind_for(&planned, "UPPER.ZIP"), BatchEntryKind::Ready);
    for ignored in ["notes.txt", "folder.zip", "hidden.zip"] {
        assert!(
            planned
                .entries
                .iter()
                .all(|entry| entry.package_name != ignored),
            "{ignored} is not a package in this folder"
        );
    }
    assert_eq!(
        snapshot(&world.installed),
        before,
        "planning writes nothing"
    );

    // Applying writes the two plain updates and nothing else, in or out of the installation.
    let applied = batch_apply(&world.state, &planned.handle).expect("apply");
    assert_eq!(applied.committed_count, 2);
    let after = snapshot(&world.installed);
    assert_eq!(after["alpha/client.lua"], b"client = 2\n");
    assert_eq!(after["beta/client.lua"], b"client = 2\n");
    assert_eq!(after["delta/client.lua"], before["delta/client.lua"]);
    assert!(
        !outside.exists(),
        "nothing was written outside the installation"
    );
}

#[test]
fn a_folder_with_too_many_packages_is_refused_whole_rather_than_cut_short() {
    let world = two_ready(["alpha", "beta"]);
    for index in 0..300 {
        fs::write(world.packages.join(format!("filler-{index:03}.zip")), b"x").expect("filler");
    }
    let failure = batch_plan(
        &world.state,
        &world.installed_handle,
        &world.packages_handle,
        world.app_data.clone(),
    )
    .expect_err("too many");
    assert_eq!(failure, crate::error::DesktopFailure::PlanLimitReached);
}

#[test]
fn an_empty_folder_is_a_plan_with_nothing_in_it() {
    let world = two_ready(["alpha", "beta"]);
    for entry in fs::read_dir(&world.packages).expect("read").flatten() {
        fs::remove_file(entry.path()).expect("remove");
    }
    let planned = plan(&world);
    assert!(planned.entries.is_empty());
    assert_eq!(planned.ready_count, 0);
    let applied = batch_apply(&world.state, &planned.handle).expect("apply");
    assert_eq!(applied.committed_count, 0);
    assert!(applied.results.is_empty());
}

#[test]
fn an_applied_batch_blocks_the_next_one_until_it_is_closed() {
    let world = two_ready(["alpha", "beta"]);
    let first = plan(&world);
    assert_eq!(
        batch_apply(&world.state, &first.handle)
            .expect("apply")
            .committed_count,
        2
    );
    assert_eq!(
        batch_apply(&world.state, &first.handle),
        Err(crate::error::DesktopFailure::PlanAlreadyApplied)
    );

    // Still on record: said by name, not as "unreadable".
    let blocked = plan(&world);
    assert_eq!(
        kind_for(&blocked, "alpha.zip"),
        BatchEntryKind::BlockedByEarlierUpdate
    );
    assert_eq!(
        kind_for(&blocked, "beta.zip"),
        BatchEntryKind::BlockedByEarlierUpdate
    );
    assert_eq!(blocked.ready_count, 0);

    close_finished_updates(&world.app_data);
    let closed = plan(&world);
    assert_eq!(kind_for(&closed, "alpha.zip"), BatchEntryKind::UpToDate);
    assert_eq!(kind_for(&closed, "beta.zip"), BatchEntryKind::UpToDate);
}

#[test]
fn the_single_screen_and_the_batch_know_what_the_other_did() {
    let world = two_ready(["alpha", "beta"]);

    // One resource through the single screen.
    let package = world.packages.join("alpha.zip");
    let handle = select(&world.state, SelectionKind::PackageFile, &package);
    let preview = crate::update::two_way_preview(
        &world.state,
        &world.installed_handle,
        &handle,
        None,
        world.app_data.clone(),
    )
    .expect("preview");
    crate::update::two_way_apply(&world.state, &preview.handle, true, &[]).expect("apply");
    close_finished_updates(&world.app_data);

    // The batch sees it as done and still offers the other.
    let planned = plan(&world);
    assert_eq!(kind_for(&planned, "alpha.zip"), BatchEntryKind::UpToDate);
    assert_eq!(kind_for(&planned, "beta.zip"), BatchEntryKind::Ready);
    assert_eq!(
        batch_apply(&world.state, &planned.handle)
            .expect("apply")
            .committed_count,
        1
    );
    close_finished_updates(&world.app_data);

    // And the single screen sees the batch's update as done.
    let package = world.packages.join("beta.zip");
    let handle = select(&world.state, SelectionKind::PackageFile, &package);
    let again = crate::update::two_way_preview(
        &world.state,
        &world.installed_handle,
        &handle,
        None,
        world.app_data.clone(),
    )
    .expect("preview");
    assert!(
        again.used_remembered_baseline,
        "it reached for what the batch kept"
    );
    assert_eq!(again.summary.review, 0);
    assert_eq!(again.summary.take_from_update, 0);
}

#[test]
fn a_file_changed_after_planning_stops_the_batch_and_nothing_after_it_is_written() {
    let world = two_ready(["alpha", "beta"]);
    let planned = plan(&world);
    // The first one in plan order changes under the batch's feet.
    fs::write(
        world.installed.join("alpha/client.lua"),
        b"someone edited this\n",
    )
    .expect("edit");
    let before_beta = snapshot(&world.installed.join("beta"));

    let applied = batch_apply(&world.state, &planned.handle).expect("apply");

    assert_eq!(applied.committed_count, 0);
    let result = |name: &str| {
        let entry = planned
            .entries
            .iter()
            .find(|entry| entry.resource.as_deref() == Some(name))
            .expect("entry");
        applied
            .results
            .iter()
            .find(|r| r.id == entry.id)
            .expect("result")
            .result
    };
    assert_eq!(result("alpha"), BatchApplyResultKind::Failed);
    assert_eq!(result("beta"), BatchApplyResultKind::NotAttempted);
    assert_eq!(snapshot(&world.installed.join("beta")), before_beta);
    assert_eq!(
        fs::read(world.installed.join("alpha/client.lua")).expect("alpha"),
        b"someone edited this\n",
        "what someone wrote in between is not overwritten"
    );
}

#[test]
fn a_folder_that_went_away_after_planning_writes_nothing() {
    let world = two_ready(["alpha", "beta"]);
    let planned = plan(&world);
    let before = snapshot(&world.installed);
    world
        .state
        .selections
        .lock()
        .expect("selections")
        .release(&world.packages_handle)
        .expect("release");
    assert!(batch_apply(&world.state, &planned.handle).is_err());
    assert_eq!(snapshot(&world.installed), before);

    // A plan that was let go of cannot be applied either.
    let again = two_ready(["alpha", "beta"]);
    let released = plan(&again);
    batch_release(&again.state, &released.handle).expect("release");
    assert_eq!(
        batch_apply(&again.state, &released.handle),
        Err(crate::error::DesktopFailure::PlanNotFound)
    );
}

#[test]
fn a_package_for_a_resource_that_is_not_there_says_so_instead_of_blaming_the_files() {
    let world = two_ready(["alpha", "beta"]);
    write_zip(
        &world.packages.join("radio.zip"),
        &[("radio/fxmanifest.lua".into(), MANIFEST.to_vec())],
    );
    let package = world.packages.join("radio.zip");
    let handle = select(&world.state, SelectionKind::PackageFile, &package);

    // The folder that holds the resources.
    let in_root = crate::update::two_way_preview(
        &world.state,
        &world.installed_handle,
        &handle,
        None,
        world.app_data.clone(),
    );
    assert_eq!(
        in_root.err(),
        Some(crate::error::DesktopFailure::PackageResourceNotInstalled)
    );

    // One resource's own folder.
    let alpha = select(
        &world.state,
        SelectionKind::InstalledRoot,
        &world.installed.join("alpha"),
    );
    let in_resource =
        crate::update::two_way_preview(&world.state, &alpha, &handle, None, world.app_data.clone());
    assert_eq!(
        in_resource.err(),
        Some(crate::error::DesktopFailure::PackageResourceNotInstalled)
    );

    // And a package that does belong there still compares, in either.
    let matching = select(
        &world.state,
        SelectionKind::PackageFile,
        &world.packages.join("alpha.zip"),
    );
    assert!(crate::update::two_way_preview(
        &world.state,
        &world.installed_handle,
        &matching,
        None,
        world.app_data.clone()
    )
    .is_ok());
    assert!(crate::update::two_way_preview(
        &world.state,
        &alpha,
        &matching,
        None,
        world.app_data.clone()
    )
    .is_ok());
}

#[test]
fn the_history_answers_line_up_with_the_rows_whatever_order_they_are_read_in() {
    use crate::undo::{history_status, history_statuses, UndoHistoryStatus};

    let world = two_ready(["alpha", "beta"]);
    let planned = plan(&world);
    assert_eq!(
        batch_apply(&world.state, &planned.handle)
            .expect("apply")
            .committed_count,
        2
    );
    close_finished_updates(&world.app_data);

    let records = crate::undo::list(&world.app_data);
    assert_eq!(records.len(), 2);
    let mut ids: Vec<String> = records.iter().map(|record| record.id.clone()).collect();
    // A row nobody has a record of sits between them and must stay unavailable in its place.
    ids.insert(1, "no-such-update".to_owned());

    let before = history_statuses(&world.app_data, &ids);
    assert_eq!(
        before,
        vec![
            UndoHistoryStatus::Available,
            UndoHistoryStatus::Unavailable,
            UndoHistoryStatus::Available
        ]
    );
    // Asking about them together says the same as asking about each alone.
    for (id, together) in ids.iter().zip(&before) {
        assert_eq!(&history_status(&world.app_data, id), together, "{id}");
    }

    // Put one back: only its own row changes, wherever it is in the list.
    let workspace = resolve_trusted_update_workspace(&world.app_data).expect("workspace");
    crate::undo::undo(&workspace, &records[0]).expect("undo");
    close_finished_updates(&world.app_data);
    let after = history_statuses(&world.app_data, &ids);
    assert_eq!(after[0], UndoHistoryStatus::Completed { preserved: 0 });
    assert_eq!(after[1], UndoHistoryStatus::Unavailable);
    assert_eq!(after[2], UndoHistoryStatus::Available);
}
