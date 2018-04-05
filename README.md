# JsseTLS

JSSE TLS examples

- Can be used with the Bouncy Castle security provider, different versions are supported based on the provided parameter
- RSA and EC keys are supported

Compile with (assuming version 1.56):
```bash
mvn clean install -Dbc.version=1.56
```

Start with:
```bash
java -jar JsseTlsServer-1.56-1.0.jar [port] [jks] [password] [alias] [BC]
```

The last paramater is optional. If it is set, the server uses the Bouncy Castle security provider and inserts it on the first place in the provider list. Otherwise, default Java security providers are used.

### Examples
```bash
java -jar JsseTlsServer-1.56-1.0.jar 4433 rsa.jks passwd rsakey BC
```
```bash
java -jar JsseTlsServer-1.56-1.0.jar 4433 ec.jks passwd ec
```

### Note
When using Bouncy Castle 1.50 or lower, the server is vulnerable to invalid curve attacks (see https://web-in-security.blogspot.de/2015/09/practical-invalid-curve-attacks.html)
