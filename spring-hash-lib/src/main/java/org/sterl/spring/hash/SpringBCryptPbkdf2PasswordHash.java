package org.sterl.spring.hash;

import java.security.SecureRandom;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.sterl.hash.Algorithm;
import org.sterl.hash.BCryptPbkdf2PasswordHash;
import org.sterl.hash.bcrypt.BCrypt;
import org.sterl.hash.bcrypt.BCryptPasswordEncoder.BCryptVersion;
import org.sterl.hash.sha.PBKDF2WithHmacSHA;

/**
 * Supports the Pbkdf2PasswordHash and the Spring Boot BCrypt.
 * 
 * <h2>Supported Algorithms:</h2>
 * <ul>
 *  <li>PBKDF2WithHmacSHA224</li>
 *  <li>PBKDF2WithHmacSHA256</li>
 *  <li>PBKDF2WithHmacSHA384</li>
 *  <li>PBKDF2WithHmacSHA512</li>
 *  <li>BCrypt</li>
 * </ul>
 * 
 * <h2>PBKDF2 Parameters:</h2>
 * <ol>
 *  <li><b>Pbkdf2PasswordHash.Algorithm</b>
 *      <ul>
 *          <li>PBKDF2WithHmacSHA224</li>
 *          <li>PBKDF2WithHmacSHA256</li>
 *          <li>PBKDF2WithHmacSHA384</li>
 *          <li>PBKDF2WithHmacSHA512</li>
 *      </ul>
 *  </li>
 *  <li><b>Pbkdf2PasswordHash.Iterations</b>
 *      <ul>
 *          <li>min 1024</li>
 *          <li>default 2048</li>
 *      </ul>
 *  </li>
 *  <li><b>Pbkdf2PasswordHash.SaltSizeBytes</b>
 *      <ul>
 *          <li>min 16</li>
 *          <li>default 32</li>
 *      </ul>
 *  </li>
 *  <li><b>Pbkdf2PasswordHash.KeySizeBytes</b>
 *      <ul>
 *          <li>min 16</li>
 *          <li>default 32</li>
 *      </ul>
 *  </li>
 * </ol>
 * <h2>BCrypt Parameters:</h2>
 * <ol>
 * <li><b>BCrypt.Version</b>
 *      <ul>
 *          <li>$2A</li>
 *          <li>$2Y</li>
 *          <li>$2B</li>
 *      </ul>
 *  </li>
 *  <li><b>BCrypt.Strength</b>
 *      <ul>
 *          <li>min 4</li>
 *          <li>max 31</li>
 *      </ul>
 *  </li>
 * </ol>
 * @see Algorithm
 * @see BCryptVersion
 * @see BCryptPbkdf2PasswordHash
 */
public class SpringBCryptPbkdf2PasswordHash implements PasswordEncoder {
    private final BCryptPbkdf2PasswordHash encoder;
    
    /**
     * Creates a new instance of {@link SpringBCryptPbkdf2PasswordHash} using {@link BCrypt} to
     * hash new passwords.
     * 
     * @param strength the log rounds to use, between 4 and 31, default is 10
     * @param version (optional) default is {@link BCryptVersion#$2A}
     * @param random (optional) {@link SecureRandom} used to hash new passwords
     * @return the {@link SpringBCryptPbkdf2PasswordHash}, never <code>null</code>
     */
    public static SpringBCryptPbkdf2PasswordHash initBCrypt(
            int strength, BCryptVersion version,  SecureRandom random) {
        
        return new SpringBCryptPbkdf2PasswordHash(
                BCryptPbkdf2PasswordHash.newBCryptPasswordEncoder(strength, version, random));
    }
    /**
     * Creates a new instance of {@link SpringBCryptPbkdf2PasswordHash} using {@link PBKDF2WithHmacSHA} to
     * hash new passwords.
     * 
     * Algorithms:
     * <pre>
     * PBKDF2WithHmacSHA224
     * PBKDF2WithHmacSHA256
     * PBKDF2WithHmacSHA384
     * PBKDF2WithHmacSHA512
     * </pre>
     * 
     * @param iterations basically the strength, default 2048
     * @param saltSizeBytes e.g. 32
     * @param keySizeBytes e.g. 32
     * @param algorithm (optional) default PBKDF2WithHmacSHA512
     * @param random (optional) {@link SecureRandom} to generate the salt
     * @return the {@link SpringBCryptPbkdf2PasswordHash}, never <code>null</code>
     */
    public static SpringBCryptPbkdf2PasswordHash initPbkdf2(
            int iterations, int saltSizeBytes,
            int keySizeBytes, Algorithm algorithm, SecureRandom random) {
        return new SpringBCryptPbkdf2PasswordHash(
                BCryptPbkdf2PasswordHash.newPBKDF2Encoder(iterations, saltSizeBytes, keySizeBytes, algorithm, random));
    }

    public SpringBCryptPbkdf2PasswordHash() {
        this.encoder = new BCryptPbkdf2PasswordHash();
    }
    public SpringBCryptPbkdf2PasswordHash(BCryptPbkdf2PasswordHash encoder) {
        this.encoder = encoder;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) return null;
        return this.encoder.encode(rawPassword);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return this.encoder.matches(rawPassword, encodedPassword);
    }
}
