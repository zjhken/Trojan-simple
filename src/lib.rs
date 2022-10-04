use std::{
    fs::{self, File},
    io::{self, BufReader},
    path::Path,
    sync::Arc,
};

use async_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use async_rustls::rustls::{
    self, internal::pemfile::rsa_private_keys, Certificate, NoClientAuth, PrivateKey, ServerConfig,
};
use log::LevelFilter;
use smol::{io::AsyncReadExt, net::TcpListener};

mod client;
mod config;
mod server;

pub fn run() {
    // config::load_config();
    // client::run_client();
    // server::run_server();
    let _ = env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .try_init();
    let _ = smol::block_on(async { task().await });
}

pub async fn task() -> io::Result<()> {
    log::info!("hahahaha");
    let tcp_listener = TcpListener::bind("0.0.0.0:9898").await?;

    let certs = load_certs(Path::new("./cert2.pem")).unwrap();
    let mut key = load_keys(Path::new("./key2.pem")).unwrap();

    let mut config = ServerConfig::new(NoClientAuth::new());
    config
        .set_single_cert(certs, key.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    // let config = rustls::ServerConfig::builder()
    //     .with_safe_default_cipher_suites()
    //     .with_safe_default_kx_groups()
    //     .with_safe_default_protocol_versions()
    //     .unwrap()
    //     .with_no_client_auth()
    //     .with_single_cert(certs, private_key)
    //     .expect("bad certificate/key");

    let tls_acceptor = async_rustls::TlsAcceptor::from(Arc::new(config));

    // let config = Arc::new(config);
    loop {
        let (stream, addr) = tcp_listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        log::info!("HTTP connection from addr {}", addr);

        let _ = smol::block_on(async move {
            log::info!("enter tls");
            let mut stream = tls_acceptor.accept(stream).await.unwrap();
            log::info!("Got tls Steam");
            let mut buf = String::new();
            match stream.read_to_string(&mut buf).await {
                Ok(n) => {
                    log::info!("Read {} bytes", n);
                    log::info!("Got HTTPS TEXT\n{}", buf);
                    Ok(()) as io::Result<()>
                }
                Err(e) => return Err(e),
            }
        });
    }
    // return Ok(());
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}

fn load_certs_old(path: &str) -> Vec<rustls::Certificate> {
    let certFile = fs::File::open(path).unwrap();
    let mut certFileReader = BufReader::new(certFile);
    let certs: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut certFileReader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();
    return certs;
}

fn load_key_old(path: &str) -> rustls::PrivateKey {
    let keyFile = fs::File::open(path).unwrap();
    let mut keyFileReader = BufReader::new(keyFile);
    let private_key: rustls::PrivateKey = rustls_pemfile::certs(&mut keyFileReader)
        .unwrap()
        .iter()
        .last()
        .map(|v| rustls::PrivateKey(v.clone()))
        .unwrap();
    return private_key;
}

#[cfg(test)]
mod test {
    use std::{
        fs::{self, File},
        io,
    };

    use rcgen::generate_simple_self_signed;

    #[test]
    fn gen_cert() -> io::Result<()> {
        let subject_alt_names = vec!["10.0.0.22".to_string(), "localhost".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
        println!("{}", cert.serialize_pem().unwrap());
        println!("{}", cert.serialize_private_key_pem());
        fs::write("./cert2.pem", cert.serialize_pem().unwrap()).unwrap();
        fs::write("./key2.pem", cert.serialize_private_key_pem()).unwrap();
        Ok(())
    }
}
