use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use crate::recovery::RecoveryRegistry;
use crate::scan::ScanRegistry;
use crate::selection::SelectionRegistry;
use crate::update::TwoWayRegistry;

pub struct DesktopAppState {
    pub selections: Mutex<SelectionRegistry>,
    pub scans: Mutex<ScanRegistry>,
    pub recoveries: Mutex<RecoveryRegistry>,
    pub two_way: Mutex<TwoWayRegistry>,
    pub operation_occupied: Arc<AtomicBool>,
}

impl Default for DesktopAppState {
    fn default() -> Self {
        Self {
            selections: Mutex::new(SelectionRegistry::default()),
            scans: Mutex::new(ScanRegistry::default()),
            recoveries: Mutex::new(RecoveryRegistry::default()),
            two_way: Mutex::new(TwoWayRegistry::default()),
            operation_occupied: Arc::new(AtomicBool::new(false)),
        }
    }
}
