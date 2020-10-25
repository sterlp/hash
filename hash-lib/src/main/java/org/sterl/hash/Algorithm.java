package org.sterl.hash;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public enum Algorithm {
    /**
     * Supported by Soteria, Java EE 
     */
    PBKDF2WithHmacSHA224,
    /**
     * Supported by Soteria, Java EE 
     */
    PBKDF2WithHmacSHA256,
    /**
     * Supported by Soteria, Java EE 
     */
    PBKDF2WithHmacSHA384,
    /**
     * Supported by Soteria, Java EE 
     */
    PBKDF2WithHmacSHA512,
    /**
     * Supported in Spring Boot
     */
    BCrypt
    ;
    
}
