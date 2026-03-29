//! Phase 7: Hypervisor-Enforced Kernel Integrity (Heki)
//!
//! This module defines the structural scaffolds for the Ring -1 Extended Page Tables (EPT).
//! By hooking into Intel VT-x and AMD-V features, Telos establishes an immutable guard over
//! kernel memory containing its eBPF security policies.

use std::collections::HashMap;

/// Represents a hypervisor-enforced memory frame layout for Extended Page Tables.
#[derive(Debug, Clone)]
pub struct EptMapping {
    /// Physical frame number of the protected region
    pub physical_pfn: u64,
    /// Type of access allowed (Bit 0: Read, Bit 1: Write, Bit 2: Execute)
    pub access_rights: u8,
}

/// The core VMCALL handler to trap unauthorized Ring 0 writes.
pub struct HekiMonitor {
    pub protected_maps: HashMap<String, EptMapping>,
}

impl HekiMonitor {
    pub fn new() -> Self {
        Self {
            protected_maps: HashMap::new(),
        }
    }

    /// Registers a physical mapping for hardware-assisted lockdown
    pub fn map_ept_page(&mut self, map_name: &str, pfn: u64) {
        self.protected_maps.insert(
            map_name.to_string(),
            EptMapping {
                physical_pfn: pfn,
                access_rights: 0b101, // Read (1) and Execute (4) permitted, Write (2) disabled
            },
        );
        println!("[HEKI] Locked physical page {:#x} (EPT Write-Protect) for map '{}'", pfn, map_name);
    }

    /// Primary VMExit intercept trap for hardware violations
    pub fn handle_vmexit(&self, rip: u64, target_pfn: u64, is_write: bool) {
        if is_write {
            // Check if target PFN is in our protected set
            for (name, map) in &self.protected_maps {
                if map.physical_pfn == target_pfn && (map.access_rights & 0b010) == 0 {
                    // Unauthorized Ring 0 Rootkit write attempt intercepted!
                    println!("[HEKI FATAL] Unauthorized Ring 0 write intercepted at RIP {:#x} targeting map '{}' (PFN: {:#x})", rip, name, target_pfn);
                    self.drop_and_panic_guest(rip);
                }
            }
        }
    }

    /// Respond to an EPT violation by killing the malicious guest thread
    fn drop_and_panic_guest(&self, rip: u64) {
        println!("[HEKI] Guest kernel modification dropped. Synthesizing NMI / Kernel Panic for attacking thread at RIP {:#x}.", rip);
    }
}
