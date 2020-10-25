package org.sterl.hash.bcrypt;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class BCryptPasswordEncoderTest {

    @Test
    void test() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        final String encoded = bCryptPasswordEncoder.encode("aaa");
        assertTrue(bCryptPasswordEncoder.matches("aaa", encoded));
        assertFalse(bCryptPasswordEncoder.matches("aaa1", encoded));
        System.out.println(encoded);
    }
    
    @Test
    void testCompatibility() {
        BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(); 
        org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder springBcrypt = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
        
        
        assertTrue(springBcrypt.matches("aaa", bcrypt.encode("aaa")));
        assertTrue(bcrypt.matches("aaa", springBcrypt.encode("aaa")));
        
        assertFalse(springBcrypt.matches("aaa1", bcrypt.encode("aaa")));
        assertFalse(bcrypt.matches("aaa1", springBcrypt.encode("aaa")));
    }

}
