package org.sterl.hash;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableSet;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.glassfish.soteria.identitystores.hash.Pbkdf2PasswordHashImpl;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion;

class BCryptPbkdf2PasswordHashTest {
    final Set<String> SUPPORTED_ALGORITHMS = unmodifiableSet(new HashSet<>(asList(
            "PBKDF2WithHmacSHA224",
            "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384",
            "PBKDF2WithHmacSHA512"
            )));


    @Test
    void testCompatibilityToJEE() {
        final Pbkdf2PasswordHashImpl jEE = new Pbkdf2PasswordHashImpl();
        BCryptPbkdf2PasswordHash passwordHash = new BCryptPbkdf2PasswordHash();
        final Map<String, String> config = new HashMap<>();

        // first encode with JEE Pbkdf2PasswordHashImpl
        for (String algo : SUPPORTED_ALGORITHMS) {
            config.put("Pbkdf2PasswordHash.Algorithm", algo);
            jEE.initialize(config);
            final String password = UUID.randomUUID().toString();
            
            assertTrue(passwordHash.matches(password, jEE.generate(password.toCharArray())));
            assertFalse(passwordHash.matches(password + "1", jEE.generate(password.toCharArray())));
        }
        
        for (Algorithm algo : Algorithm.values()) {
            if (algo != Algorithm.BCrypt) {
                passwordHash = new BCryptPbkdf2PasswordHash(algo);
                final String password = UUID.randomUUID().toString();
                
                assertTrue(jEE.verify(password.toCharArray(), passwordHash.encode(password)));
                assertFalse(jEE.verify("aaa".toCharArray(), passwordHash.encode(password)));
                assertFalse(jEE.verify(password.toCharArray(), passwordHash.encode("aaa")));
            }
        }
    }
    
    @Test
    void testCompatibilityToSpring() {
        final BCryptPbkdf2PasswordHash passwordHash = new BCryptPbkdf2PasswordHash();
        
        for (BCryptVersion version : BCryptVersion.values()) {
            BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(version);
            
            final String password = UUID.randomUUID().toString();
            assertTrue(bcrypt.matches(password, passwordHash.encode(password)));
            assertTrue(passwordHash.matches(password, bcrypt.encode(password)));
            
            assertFalse(bcrypt.matches("aa", passwordHash.encode(password)));
            assertFalse(passwordHash.matches(password, bcrypt.encode("aa")));
        }
    }

}
