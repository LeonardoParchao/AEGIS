use pyo3::prelude::*;
use std::sync::Mutex;
use tokio::runtime::Runtime;

pub mod http_engine;

#[cfg(unix)]
pub mod network_engine;

#[cfg(unix)]
pub mod verification_engine;

// Global Tokio runtime
lazy_static::lazy_static! {
    static ref RT: Mutex<Option<Runtime>> = Mutex::new(None);
}

#[pymodule]
fn aegis_userspace(_py: Python, m: &PyModule) -> PyResult<()> {
    // Initialize Tokio runtime
    let mut rt_guard = RT.lock().unwrap();
    if rt_guard.is_none() {
        *rt_guard = Some(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .expect("Failed to create Tokio runtime")
        );
    }
    drop(rt_guard);

    // HTTP engine submodule
    let http_module = PyModule::new(_py, "http_engine")?;
    http_module.add_function(wrap_pyfunction!(http_engine::send_http_request, _py)?)?;
    http_module.add_function(wrap_pyfunction!(http_engine::send_batch_requests, _py)?)?;
    m.add_submodule(http_module)?;

    // Network engine submodule (Unix only)
    #[cfg(unix)]
    {
        let network_module = PyModule::new(_py, "network_engine")?;
        network_module.add_function(wrap_pyfunction!(network_engine::inject_pcap, _py)?)?;
        network_module.add_function(wrap_pyfunction!(network_engine::track_network_state, _py)?)?;
        m.add_submodule(network_module)?;
    }

    // Verification engine submodule (Unix only)
    #[cfg(unix)]
    {
        let verification_module = PyModule::new(_py, "verification_engine")?;
        verification_module.add_function(wrap_pyfunction!(verification_engine::load_ebpf_program, _py)?)?;
        verification_module.add_function(wrap_pyfunction!(verification_engine::verify_vulnerability, _py)?)?;
        m.add_submodule(verification_module)?;
    }

    Ok(())
}
