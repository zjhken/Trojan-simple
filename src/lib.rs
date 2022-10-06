use std::{
    fs::{self, File},
    io::{self, BufReader},
    path::Path,
    sync::Arc,
};

use async_rustls::rustls::{
    internal::pemfile::{self, certs, pkcs8_private_keys},
    SupportedCipherSuite,
};
use async_rustls::{
    rustls::{
        self, internal::pemfile::rsa_private_keys, Certificate, CipherSuite, NoClientAuth,
        PrivateKey, ServerConfig, ALL_CIPHERSUITES,
    },
    TlsAcceptor,
};
use error::CustError;
use httparse::{Request, EMPTY_HEADER};
use log::LevelFilter;
use smol::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

mod client;
mod config;
mod error;
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
    let tcp_listener = TcpListener::bind("0.0.0.0:29898").await?;

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

            let mut headers = [EMPTY_HEADER; 64];
            let mut req = Request::new(&mut headers);

            let mut buf = [0u8; 2024];
            stream.read(&mut buf).await.unwrap();
            req.parse(&buf).unwrap();
            log::info!("{}", String::from_utf8_lossy(&buf));
            // log::info!("Method = {:?}", req.method.unwrap());
            // log::info!("path = {:?}", req.path.unwrap());
            // for header in req.headers {
            //     if header.name == "Proxy-Authorization" {
            //         log::info!("Auth = {:?}", String::from_utf8_lossy(header.value));
            //     }
            // }

            stream
                .write_all("HTTP/1.1 200 Connection established\r\n\r\n".as_bytes())
                .await
                .unwrap();
            log::info!("Returned");

            return Ok(()) as io::Result<()>;
        });
    }
    // return Ok(());
}

pub async fn task2() -> io::Result<()> {
    let tcp_listener = TcpListener::bind("0.0.0.0:9898").await?;
    log::debug!("tls listen addr = {}", "9898");

    let cert_path = Path::new("./cert2.pem");
    let key_path = Path::new("./key2.pem");
    let certs = load_cert(&cert_path)?;
    let mut keys = load_key(&key_path)?;

    let mut tls_config = ServerConfig::new(NoClientAuth::new());
    tls_config
        .set_single_cert(certs, keys.remove(0))
        .map_err(|e| new_error(format!("invalid cert {}", e.to_string())))?;

    tls_config.ciphersuites = get_cipher_suite(None)?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let (stream, addr) = tcp_listener.accept().await?;
    log::info!("tcp connection from {}", addr);
    let stream = tls_acceptor.accept(stream).await?;
    Ok(())
}

fn get_cipher_suite(cipher: Option<Vec<String>>) -> io::Result<Vec<&'static SupportedCipherSuite>> {
    if cipher.is_none() {
        return Ok(ALL_CIPHERSUITES.to_vec());
    }
    let cipher = cipher.unwrap();
    let mut result = Vec::new();

    for name in cipher {
        let mut found = false;
        for i in ALL_CIPHERSUITES.to_vec() {
            if name == get_cipher_name(i) {
                result.push(i);
                found = true;
                log::debug!("cipher: {} applied", name);
                break;
            }
        }
        if !found {
            return Err(new_error(format!("bad cipher: {}", name)));
        }
    }
    Ok(result)
}

fn get_cipher_name(cipher: &SupportedCipherSuite) -> &'static str {
    /*
    /// A list of all the cipher suites supported by rustls.
    pub static ALL_CIPHERSUITES: [&SupportedCipherSuite; 9] = [
        // TLS1.3 suites
        &TLS13_CHACHA20_POLY1305_SHA256,
        &TLS13_AES_256_GCM_SHA384,
        &TLS13_AES_128_GCM_SHA256,

        // TLS1.2 suites
        &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
     */
    match cipher.suite {
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS13_CHACHA20_POLY1305_SHA256",
        CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS13_AES_256_GCM_SHA384",
        CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS13_AES_128_GCM_SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        }
        _ => "???",
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}

fn load_cert(path: &Path) -> io::Result<Vec<Certificate>> {
    pemfile::certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls cert"))
}

fn load_key(path: &Path) -> io::Result<Vec<PrivateKey>> {
    let pkcs8_key = pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls pkcs8 key"))?;
    if pkcs8_key.len() != 0 {
        return Ok(pkcs8_key);
    }
    let rsa_key = pemfile::rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls rsa key"))?;
    if rsa_key.len() != 0 {
        return Ok(rsa_key);
    }
    return Err(new_error("no valid key found"));
}

fn new_error<T: ToString>(message: T) -> io::Error {
    return CustError::new(format!("tls: {}", message.to_string())).into();
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
        error::Error,
        fs::{self, File},
        io::{self, BufReader},
        path::Path,
    };

    use async_rustls::rustls::{internal::pemfile, PrivateKey};
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

    #[test]
    fn test_tls() -> Result<(), std::io::Error> {
        Ok(())
    }
}
