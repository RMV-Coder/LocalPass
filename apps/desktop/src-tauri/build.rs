// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See apps/desktop/LICENSE.

//! Tauri build script: embeds the frontend `dist/`, the config, and icons into
//! the binary and runs the platform build steps.

fn main() {
    tauri_build::build();
}
