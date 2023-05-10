## Open DICE Profile implementation

### Manual Config (`openssl`)

```bash
openssl genpkey -algorithm ed25519 -out priv.pem
openssl pkey -in priv.pem -pubout -out pub.pem
openssl req -key priv.pem -out cert.csr
openssl x509 -signkey priv.pem -in cert.csr -req -days 365 -out cert.crt
```
