use libectf::{frame::Frame, subscription::SubscriptionData};
use pyo3::prelude::*;
use rand::rngs::OsRng;
use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs1v15::SigningKey, sha2::Sha256, RsaPrivateKey};

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
        let frame = Frame(frame.try_into().unwrap());
        rkyv::to_bytes::<rkyv::rancor::Error>(&frame.encode(timestamp, channel, self.secrets.as_slice())).unwrap().into_vec()
    }
}

#[pyfunction]
fn gen_subscription(secrets: Vec<u8>, device_id: u32, start: u64, end: u64, channel: u32) -> Vec<u8> {
    let data = SubscriptionData::generate(secrets.as_slice(), start, end, channel, device_id);

    let mut res = rkyv::to_bytes::<rkyv::rancor::Error>(&data.header).unwrap().into_vec();
    
    for key in data.keys {
        res.extend(rkyv::to_bytes::<rkyv::rancor::Error>(&key).unwrap().into_iter());
    }

    res
}

#[pyfunction]
#[allow(unused_variables)]
fn gen_secrets(channels: Vec<u32>) -> Vec<u8> {
    let private_key = RsaPrivateKey::new(&mut OsRng, 512).unwrap();
    let signing_key = SigningKey::<Sha256>::new(private_key);
    signing_key.to_pkcs1_der().unwrap().as_bytes().to_vec()
}

#[pymodule]
fn ectf25_design_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Encoder>()?;
    m.add_function(wrap_pyfunction!(gen_secrets, m)?)?;
    m.add_function(wrap_pyfunction!(gen_subscription, m)?)?;

    Ok(())
}
