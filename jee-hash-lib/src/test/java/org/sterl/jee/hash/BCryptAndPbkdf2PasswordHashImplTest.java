package org.sterl.jee.hash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.sterl.hash.Algorithm;
import org.sterl.hash.bcrypt.BCryptPasswordEncoder.BCryptVersion;

class BCryptAndPbkdf2PasswordHashImplTest {

    final BCryptAndPbkdf2PasswordHashImpl subject = new BCryptAndPbkdf2PasswordHashImpl();
    
    @Test
    void testDefaultInit() {
        String pass = subject.generate("pass".toCharArray());
        assertTrue(subject.verify("pass".toCharArray(), pass));
        assertFalse(subject.verify("pass2".toCharArray(), pass));
    }
    
    @Test
    void testInitPBKDF2() {
        final Map<String, String> parameters = new HashMap<>();
        
        parameters.put(BCryptAndPbkdf2PasswordHashImpl.ALGORITHM, Algorithm.PBKDF2WithHmacSHA384.name());
        subject.initialize(parameters);
        assertEquals(Algorithm.PBKDF2WithHmacSHA384, subject.getAlgorithm());
        String encoded = verify(subject);
        assertTrue(encoded.startsWith(Algorithm.PBKDF2WithHmacSHA384.name()), "Should start with " 
                + Algorithm.PBKDF2WithHmacSHA384 + " but was: " + encoded);

        parameters.put(BCryptAndPbkdf2PasswordHashImpl.PBKDF2_ITERATIONS, "1066");
        subject.initialize(parameters);
        assertEquals(1066, subject.getPbkdf2Iterations());
        verify(subject);

        parameters.put(BCryptAndPbkdf2PasswordHashImpl.PBKDF2_KEYSIZE, "31");
        subject.initialize(parameters);
        assertEquals(31, subject.getPbkdf2KeySizeBytes());
        verify(subject);
        
        parameters.put(BCryptAndPbkdf2PasswordHashImpl.PBKDF2_SALTSIZE, "31");
        subject.initialize(parameters);
        assertEquals(31, subject.getPbkdf2SaltSizeBytes());
        verify(subject);
    }
    
    @Test
    void testInitBCrypt() {
        final Map<String, String> parameters = new HashMap<>();
        
        parameters.put(BCryptAndPbkdf2PasswordHashImpl.ALGORITHM, Algorithm.BCrypt.name());
        subject.initialize(parameters);
        assertEquals(Algorithm.BCrypt, subject.getAlgorithm());
        verify(subject);

        parameters.put(BCryptAndPbkdf2PasswordHashImpl.BCRYPT_STRENGTH, "4");
        subject.initialize(parameters);
        assertEquals(4, subject.getBCryptStrength());
        verify(subject);

        parameters.put(BCryptAndPbkdf2PasswordHashImpl.BCRYPT_VERSION, "$2B");
        subject.initialize(parameters);
        assertEquals(BCryptVersion.$2B, subject.getBCryptVersion());
        String encoded = verify(subject);
        System.out.println(encoded);
        assertTrue(encoded.startsWith("$2b"), "Should start with $2b but was: " + encoded);
    }
    
    @Test
    void testWrongParam() {
        
        assertThrows(IllegalArgumentException.class, () -> {
            final Map<String, String> parameters = new HashMap<>();
            parameters.put(BCryptAndPbkdf2PasswordHashImpl.ALGORITHM, "Foo");
            subject.initialize(parameters);
        });
        
        assertThrows(IllegalArgumentException.class, () -> {
            final Map<String, String> parameters = new HashMap<>();
            parameters.put(BCryptAndPbkdf2PasswordHashImpl.ALGORITHM, Algorithm.BCrypt.name());
            parameters.put(BCryptAndPbkdf2PasswordHashImpl.PBKDF2_ITERATIONS, "22");
            subject.initialize(parameters);
        });
        
        assertThrows(IllegalArgumentException.class, () -> {
            final Map<String, String> parameters = new HashMap<>();
            parameters.put(BCryptAndPbkdf2PasswordHashImpl.ALGORITHM, Algorithm.PBKDF2WithHmacSHA224.name());
            parameters.put(BCryptAndPbkdf2PasswordHashImpl.BCRYPT_STRENGTH, "22");
            subject.initialize(parameters);
        });
    }
    
    private String verify(BCryptAndPbkdf2PasswordHashImpl subject) {
        final String encodedPass1 = subject.generate("pass1".toCharArray());
        final String encodedPass2 = subject.generate("pass2".toCharArray());
        
        assertNotNull(encodedPass1);
        assertNotNull(encodedPass2);
        
        assertTrue(subject.verify("pass1".toCharArray(), encodedPass1));
        assertTrue(subject.verify("pass2".toCharArray(), encodedPass2));
        
        assertFalse(subject.verify(null, encodedPass1));
        assertFalse(subject.verify("pass2".toCharArray(), encodedPass1));
        assertFalse(subject.verify("pass1".toCharArray(), encodedPass2));
        
        return encodedPass1;
    }
}
