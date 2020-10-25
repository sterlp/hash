package org.sterl.spring.hash;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.sterl.hash.Algorithm;
import org.sterl.hash.bcrypt.BCryptPasswordEncoder.BCryptVersion;

class SpringBCryptPbkdf2PasswordHashTest {

    SpringBCryptPbkdf2PasswordHash subject = new SpringBCryptPbkdf2PasswordHash();
    
    @Test
    void testDefaultInit() {
        String pass = subject.encode("pass");
        assertTrue(subject.matches("pass", pass));
        assertFalse(subject.matches("pass2", pass));
    }
    
    @Test
    void testInitPBKDF2() {
        subject = SpringBCryptPbkdf2PasswordHash.initPbkdf2(1066, 24, 24, Algorithm.PBKDF2WithHmacSHA224, null);
        verify(subject);
    }
    
    @Test
    void testInitBCrypt() {
        subject = SpringBCryptPbkdf2PasswordHash.initBCrypt(6, BCryptVersion.$2Y, null);
        verify(subject);
    }
    
    private void verify(SpringBCryptPbkdf2PasswordHash subject) {
        final String encodedPass1 = subject.encode("pass1");
        final String encodedPass2 = subject.encode("pass2");
        
        assertNotNull(encodedPass1);
        assertNotNull(encodedPass2);
        
        assertTrue(subject.matches("pass1", encodedPass1));
        assertTrue(subject.matches("pass2", encodedPass2));
        
        assertFalse(subject.matches(null, encodedPass1));
        assertFalse(subject.matches("pass2", encodedPass1));
        assertFalse(subject.matches("pass1", encodedPass2));
    }
}
