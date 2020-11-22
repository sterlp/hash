![Hash Lib CI](https://github.com/sterlp/hash/workflows/Hash%20Lib%20CI/badge.svg)

# Hash Lib Cli
Tool to create BCrypt and PBKDF2 hashes of passwords directly in the command line:

Download latest version of **hash-cli** here: https://github.com/sterlp/hash/releases

## Create a BCrpyt password hash
```
java -jar hash-cli.jar mypassword
> $2a$10$m4hjjVjjGD36bgHlblJaweMDrGelSO1lx4osfpNi/7DN9ZvTzMqA6
```

## Create a Hash with a specific algorithm
```
java -jar hash-cli.jar -a PBKDF2WithHmacSHA512 -p mypassword
> PBKDF2WithHmacSHA512:2048:ilIYz4CirlKeZfa59Tu9Dlruc69zaAxGyDb0OOcpppM=:HMv6yD8WUKSM2XY6jHIuzz9ShXX1wj120Njb0TptJ6hBBWAFnOdx0xR1hvz9ICtp91sdBxRaMyU8LsYZCIuP9g==
```

## Verify a password hash
```
java -jar hash-cli.jar -a PBKDF2WithHmacSHA512 -p mypassword -h PBKDF2WithHmacSHA512:2048:ilIYz4CirlKeZfa59Tu9Dlruc69zaAxGyDb0OOcpppM=:HMv6yD8WUKSM2XY6jHIuzz9ShXX1wj120Njb0TptJ6hBBWAFnOdx0xR1hvz9ICtp91sdBxRaMyU8LsYZCIuP9g==
> true
```

# hash-lib

Common lib which provides a common Hash algorithms for JEE and Spring Boot:

- BCrypt
- PBKDF2WithHmacSHA224
- PBKDF2WithHmacSHA256
- PBKDF2WithHmacSHA384
- PBKDF2WithHmacSHA512

## jee-hash-lib

Support BCrypt and PBKDF2 password hash and verification. As so be compatible with existing JEE JDBC user stores and
Spring Boot user stores.

## Usage
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
## Maven import JEE
```xml
<dependency>
  <groupId>org.sterl.hash</groupId>
  <artifactId>jee-hash-lib</artifactId>
  <version>0.1.0</version>
</dependency>
```

# Base Lib
```xml
<dependency>
  <groupId>org.sterl.hash</groupId>
  <artifactId>hash-lib</artifactId>
  <version>0.1.0</version>
</dependency>
```

- Release: https://oss.sonatype.org/content/repositories/releases/org/sterl/hash/
- Snapshot: https://oss.sonatype.org/content/repositories/snapshots/org/sterl/hash/

## How to release

- `mvn versions:set -DnewVersion=x.x.x-SNAPSHOT`
- `mvn clean install -Prelease`
- `mvn deploy`
