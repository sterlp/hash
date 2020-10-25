package org.sterl.hash.sha;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableSet;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.glassfish.soteria.identitystores.hash.Pbkdf2PasswordHashImpl;
import org.junit.jupiter.api.Test;

class PBKDF2WithHmacSHATest {
    final Set<String> SUPPORTED_ALGORITHMS = unmodifiableSet(new HashSet<>(asList(
            "PBKDF2WithHmacSHA224",
            "PBKDF2WithHmacSHA256",
            "PBKDF2WithHmacSHA384",
            "PBKDF2WithHmacSHA512"
            )));

    // PBKDF2WithHmacSHA512:2048:l6Qaih9Knjedzkg1EUt53CXop9lONYolXdxA0ZqdWXc=:vXkIN810hdSlPZR3BUP6Ie0bybVxtwpSjQB+g5Yp6xM=

    // ~16ms for PBKDF2WithHmacSHA512
    // ~16ms for PBKDF2WithHmacSHA384
    // ~11ms for PBKDF2WithHmacSHA256
    @Test
    void testSpeed() {
        final int iterations = 5;
        final PBKDF2WithHmacSHA pbdf2 = new PBKDF2WithHmacSHA();
        long totalTime = 0, time;
        
        for (int i = 0; i < iterations; i++) {
            time = System.nanoTime();
            final String encodedPwd = pbdf2.encode("test1");
            assertTrue(pbdf2.matches("test1", encodedPwd));
            assertFalse(pbdf2.matches("test", encodedPwd));
            totalTime += System.nanoTime() - time;
        }
        System.out.println( Duration.ofNanos(totalTime / iterations).toMillis() + "ms" );
    }
    
    @Test
    void testCompatibilityToJEE() {
        final Pbkdf2PasswordHashImpl jEE = new Pbkdf2PasswordHashImpl();
        final PBKDF2WithHmacSHA pbdf2 = new PBKDF2WithHmacSHA();
        final Map<String, String> config = new HashMap<>();

        for (String algo : SUPPORTED_ALGORITHMS) {
            config.put("Pbkdf2PasswordHash.Algorithm", algo);
            jEE.initialize(config);
            final String password = UUID.randomUUID().toString();
            
            assertTrue(pbdf2.matches(password, jEE.generate(password.toCharArray())));
            assertTrue(jEE.verify(password.toCharArray(), pbdf2.encode(password)));
            
            assertFalse(pbdf2.matches(password + "1", jEE.generate(password.toCharArray())));
            assertFalse(jEE.verify(password.toCharArray(), pbdf2.encode(password + "1")));
        }
    }
}
