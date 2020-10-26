# hash-lib

Common lib which provides a common Hash algorithms for JEE and Spring Boot:

- BCrypt
- PBKDF2WithHmacSHA224
- PBKDF2WithHmacSHA256
- PBKDF2WithHmacSHA384
- PBKDF2WithHmacSHA512

# jee-hash-lib

```java
import javax.annotation.security.DeclareRoles;
import javax.enterprise.context.ApplicationScoped;
import javax.security.enterprise.authentication.mechanism.http.BasicAuthenticationMechanismDefinition;
import javax.security.enterprise.identitystore.DatabaseIdentityStoreDefinition;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import org.sterl.jee.hash.BCryptAndPbkdf2PasswordHash;

@ApplicationScoped
@BasicAuthenticationMechanismDefinition(realmName = "jee-basic")
@DeclareRoles({ "admin", "user" }) // this authorities are allowed
@DatabaseIdentityStoreDefinition(
    callerQuery = "select password from users where enabled = true AND username = ?",
    groupsQuery = "select authority from authorities where username = ?",
    dataSourceLookup = "jdbc/identity-store",
    hashAlgorithm = BCryptAndPbkdf2PasswordHash.class,
    hashAlgorithmParameters = {
        "Algorithm=PBKDF2WithHmacSHA512"
    }
)
@ApplicationPath("")
public class ApplicationConfiguration extends Application {
    
}
```

# Maven Central
```xml
<dependency>
  <groupId>org.sterl.hash</groupId>
  <artifactId>hash-lib</artifactId>
  <version>0.1.0</version>
</dependency>
```

- https://oss.sonatype.org/content/repositories/releases/org/sterl/hash/hash-lib/0.1.0/
- https://oss.sonatype.org/content/repositories/snapshots/org/sterl/hash/hash-lib/0.1.0-SNAPSHOT/

## How to release

- `mvn clean install -Prelease`
- `mvn deploy`