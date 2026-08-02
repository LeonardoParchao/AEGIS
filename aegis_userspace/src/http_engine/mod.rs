use pyo3::prelude::*;
use pyo3::types::PyDict;
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;

pub mod client;

#[cfg(unix)]
pub mod fuzzer;

#[pyfunction]
pub fn send_http_request(
    py: Python,
    url: String,
    method: String,
    headers: Option<HashMap<String, String>>,
    body: Option<String>,
) -> PyResult<Py<PyDict>> {
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        let mut request = match method.to_lowercase().as_str() {
            "get" => client.get(&url),
            "post" => client.post(&url),
            "put" => client.put(&url),
            "delete" => client.delete(&url),
            "patch" => client.patch(&url),
            _ => return Err(anyhow::anyhow!("Unsupported HTTP method").into()),
        };

        if let Some(hdrs) = headers {
            for (key, value) in hdrs {
                request = request.header(&key, &value);
            }
        }

        if let Some(bdy) = body {
            request = request.body(bdy);
        }

        let response = request.send().await?;
        let status = response.status().as_u16();
        let response_headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let response_body = response.text().await?;

        Ok::<(u16, HashMap<String, String>, String), anyhow::Error>((
            status,
            response_headers,
            response_body,
        ))
    });

    match result {
        Ok((status, headers, body)) => {
            let dict = PyDict::new(py);
            dict.set_item("status", status)?;
            dict.set_item("headers", headers)?;
            dict.set_item("body", body)?;
            Ok(dict.into())
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
    }
}

#[pyfunction]
pub fn send_batch_requests(
    py: Python,
    requests: Vec<HashMap<String, String>>,
) -> PyResult<Vec<Py<PyDict>>> {
    let rt = tokio::runtime::Runtime::new()?;
    let results = rt.block_on(async {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(100)
            .build()?;

        let mut tasks = Vec::new();
        for req_map in requests {
            let client_clone = client.clone();
            let task = tokio::spawn(async move {
                let url = req_map.get("url").cloned().unwrap_or_default();
                let method = req_map.get("method").cloned().unwrap_or_else(|| "GET".to_string());
                
                let mut request = match method.to_lowercase().as_str() {
                    "get" => client_clone.get(&url),
                    "post" => client_clone.post(&url),
                    "put" => client_clone.put(&url),
                    "delete" => client_clone.delete(&url),
                    "patch" => client_clone.patch(&url),
                    _ => return Err::<(u16, String), anyhow::Error>(anyhow::anyhow!("Unsupported method").into()),
                };

                if let Some(body) = req_map.get("body") {
                    request = request.body(body.clone());
                }

                let response = request.send().await?;
                let status = response.status().as_u16();
                let body = response.text().await?;
                Ok((status, body))
            });
            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(Ok((status, body))) => results.push((status, body)),
                Ok(Err(e)) => results.push((0, e.to_string())),
                Err(e) => results.push((0, e.to_string())),
            }
        }

        Ok::<Vec<(u16, String)>, anyhow::Error>(results)
    });

    match results {
        Ok(responses) => {
            let py_results = responses
                .into_iter()
                .map(|(status, body)| {
                    let dict = PyDict::new(py);
                    dict.set_item("status", status).unwrap();
                    dict.set_item("body", body).unwrap();
                    dict.into()
                })
                .collect();
            Ok(py_results)
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
    }
}
