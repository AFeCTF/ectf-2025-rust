use libectf::{crypto::encode, packet::Frame, uart::encode_to_vec};
use pyo3::prelude::*;
use rand::{rngs::OsRng, TryRngCore};

#[pyclass]
struct Encoder {
    secrets: Vec<u8>
}

#[pymethods]
impl Encoder {
    #[new]
    fn new(secrets: Vec<u8>) -> Self {
        Self { secrets }
    }

    fn encode(&self, channel: u32, frame: Vec<u8>, timestamp: u64) -> Vec<u8> {
        encode_to_vec(&encode(&Frame(frame.try_into().unwrap()), timestamp, channel, self.secrets.as_slice()))
    }
}

#[pyfunction]
fn gen_subscription(secrets: Vec<u8>, device_id: u32, start: u64, end: u64, channel: u32) -> Vec<u8> {
    let data = libectf::crypto::gen_subscription(secrets.as_slice(), start, end, channel, device_id);

    let mut res = encode_to_vec(&data.header);
    
    for key in data.keys {
        res.extend(encode_to_vec(&key));
    }

    res
}

#[pyfunction]
#[allow(unused_variables)]
fn gen_secrets(channels: Vec<u32>) -> Vec<u8> {
    let mut secrets = [0u8; 32];
    OsRng.try_fill_bytes(&mut secrets).unwrap();
    secrets.to_vec()
}

#[pymodule]
fn ectf25_design_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Encoder>()?;
    m.add_function(wrap_pyfunction!(gen_secrets, m)?)?;
    m.add_function(wrap_pyfunction!(gen_subscription, m)?)?;

    Ok(())
}
