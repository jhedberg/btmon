//! Tables generated from the Bluetooth SIG Assigned Numbers documents.
//!
//! Regenerate with `tools/gen_assigned_numbers.py`.

mod ad_types;
mod appearance;
mod cod;
mod company;
mod psm;
mod uuid16;

pub use ad_types::AD_TYPES;
pub use appearance::{APPEARANCE_CATEGORIES, APPEARANCE_SUBCATEGORIES};
pub use cod::{COD_MAJOR, COD_MINOR, COD_MINOR_BITS, COD_SERVICES, COD_SUBMINOR};
pub use company::COMPANIES;
pub use psm::PSMS;
pub use uuid16::UUID16;

/// Binary search helper for the sorted `(key, name)` tables in this module.
pub fn lookup<K: Ord + Copy>(table: &'static [(K, &'static str)], key: K) -> Option<&'static str> {
    table
        .binary_search_by_key(&key, |(k, _)| *k)
        .ok()
        .map(|i| table[i].1)
}

/// Name of a company identifier.
pub fn company_name(id: u16) -> Option<&'static str> {
    lookup(COMPANIES, id)
}

/// Name of a 16-bit UUID (any SIG namespace).
pub fn uuid16_name(uuid: u16) -> Option<&'static str> {
    lookup(UUID16, uuid)
}

/// Name of an advertising / EIR data type.
pub fn ad_type_name(ad_type: u8) -> Option<&'static str> {
    lookup(AD_TYPES, ad_type)
}

/// Name of a fixed PSM.
pub fn psm_name(psm: u16) -> Option<&'static str> {
    lookup(PSMS, psm)
}

/// Human readable appearance, e.g. `Computer: Laptop`.
pub fn appearance_name(value: u16) -> Option<String> {
    let cat = lookup(APPEARANCE_CATEGORIES, value >> 6)?;
    match lookup(APPEARANCE_SUBCATEGORIES, value) {
        Some(sub) => Some(format!("{cat}: {sub}")),
        None if value & 0x3f == 0 => Some(cat.to_string()),
        None => Some(format!("{cat}: Unknown")),
    }
}
