#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(not(target_os = "linux"))]
pub fn run(_args: crate::Args) -> crate::Result<()> {
    eprintln!("ronly only runs on Linux");
    std::process::exit(1);
}
