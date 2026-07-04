// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

// On Windows in release, don't spawn an extra console window behind the GUI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Desktop binary entry point. All logic lives in the library crate so it can be
//! unit-tested and reused by a future mobile target; this just calls [`run`].

fn main() {
    localpass_desktop_lib::run();
}
