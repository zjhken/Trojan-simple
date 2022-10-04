# How to create self signed cert & key with IP address
create a file `cert_req_config.ini`
```ini
[req]
default_bits  = 2048
distinguished_name = req_distinguished_name
req_extensions = req_ext
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
countryName = XX
stateOrProvinceName = N/A
localityName = N/A
organizationName = Self-signed certificate
commonName = 10.0.0.22: Self-signed certificate

[req_ext]
subjectAltName = @alt_names

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 10.0.0.22
```

```bash
openssl req -new -nodes -x509 -days 365 -keyout domain.key -out domain.crt -config ./cert_req_config.ini
openssl req      -nodes -x509 -days 730 -newkey rsa:2048 -keyout key.pem -out cert.pem -config ./cert_req_config.ini
```

