# cas-openid-client

This application was built to test CAS OpenId implementation, specifically the Stateless mode.

# Build

```
mvn clean package
```

# Run

```
java -jar openid-client-1.0-SNAPSHOT.jar
```

Access the app at: `https://localhost:9000/openid/auth`

If you want to test stateless.mode (no association betwen RP and OP) change the value `openid-associate` in `config.properties` and rerun the test