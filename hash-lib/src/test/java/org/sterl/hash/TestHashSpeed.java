package org.sterl.hash;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.sterl.hash.bcrypt.BCryptPasswordEncoder;
import org.sterl.hash.sha.PBKDF2WithHmacSHA;

class TestHashSpeed {

    @Test
    void testSpeedPBKDF2() {
        runTest(new PBKDF2WithHmacSHA(), 5);
    }
    
    @Test
    void testSpeedBCryptPasswordEncoder() {
        runTest(new BCryptPasswordEncoder(), 5);
    }
    
    @Test
    void testSpeedBCryptPbkdf2PasswordHash() {
        runTest(new BCryptPbkdf2PasswordHash(), 5);
    }
    
    private void runTest(PasswordHasher hasher, int iterations) {
        long totalTime = 0, time;
        
        for (int i = 0; i < iterations; i++) {
            time = System.nanoTime();
            final String encodedPwd = hasher.encode("test1");
            assertTrue(hasher.matches("test1", encodedPwd));
            assertFalse(hasher.matches("test", encodedPwd));
            totalTime += System.nanoTime() - time;
        }
        System.out.println(hasher + ": " + Duration.ofNanos(totalTime / iterations).toMillis() + "ms" );
    }
}
