package org.sterl.hash;

import java.security.SecureRandom;
import java.util.Objects;

import org.sterl.hash.bcrypt.BCrypt;
import org.sterl.hash.bcrypt.BCryptPasswordEncoder;
import org.sterl.hash.bcrypt.BCryptPasswordEncoder.BCryptVersion;
import org.sterl.hash.sha.PBKDF2WithHmacSHA;

/**
 * Main class which should be used to hash and to match the passwords. This class delegates
 * the work either to {@link PBKDF2WithHmacSHA} for Java EE algorithms and {@link BCryptPasswordEncoder}
 * for Spring boot supported security stores.
 * 
 * <p>
 * Support the following hash {@link Algorithm}:
 * <blockquote><pre>
PBKDF2WithHmacSHA224
PBKDF2WithHmacSHA256
PBKDF2WithHmacSHA384
PBKDF2WithHmacSHA512
BCrypt
 * </pre></blockquote>
 * 
 * <p>
 * The encoded format as follows for *SHA* algorithms:
 * <blockquote><pre>
{@code <algorithm>:<iterations>:<base64(salt)>:<base64(hash)>}
 * </pre></blockquote>
 * Where:
 * <ul>
 *  <li><i>algorithm</i> -- the algorithm used to generate the hash
 *  <li><i>iterations</i> -- the number of iterations used to generate the hash
 *  <li><i>base64(salt)</i> -- the salt used to generate the hash, base64-encoded
 *  <li><i>base64(hash)</i> -- the hash value, base64-encoded
 * </ul>
 * For The encoded format as follows for *BCrypt algorithm:
 * <blockquote><pre>
{@code <spring boot BCrypt encoded password>}
 * </pre></blockquote>
 * </p>
 * @see https://github.com/payara/patched-src-security-soteria/blob/master/impl/src/main/java/org/glassfish/soteria/identitystores/hash/Pbkdf2PasswordHashImpl.java
 * @see https://github.com/spring-projects/spring-security/blob/master/crypto/src/main/java/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.java
 */
public class BCryptPbkdf2PasswordHash implements PasswordHasher {
    /** the log rounds to use, between 4 and 31, default is 10 */
    public final static int DEFAULT_BCRYPT_STRENGTH = 10;
    public final static BCryptVersion DEFAULT_VERSION = BCryptVersion.$2A;

    private final PasswordHasher defaultHasher;
    private final PBKDF2WithHmacSHA pbkdf2WithHmacSHA;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    
    /**
     * Creates a new instance of {@link BCryptPbkdf2PasswordHash} using {@link BCrypt} to
     * hash new passwords.
     * 
     * @param strength the log rounds to use, between 4 and 31, default is 10
     * @param version (optional) default is {@link BCryptVersion#$2A}
     * @param random (optional) {@link SecureRandom} used to hash new passwords
     * @return the {@link BCryptPbkdf2PasswordHash}, never <code>null</code>
     */
    public static BCryptPbkdf2PasswordHash newBCryptPasswordEncoder(
            int strength, BCryptVersion version,  SecureRandom random) {
        if (version == null) version = DEFAULT_VERSION;
        if (random == null) random = new SecureRandom();
        
        final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(version, strength, random);
        return new BCryptPbkdf2PasswordHash(bcrypt, new PBKDF2WithHmacSHA(), bcrypt);
    }
    
    /**
     * Creates a new instance of {@link BCryptPbkdf2PasswordHash} using {@link PBKDF2WithHmacSHA} to
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
     */
    public static BCryptPbkdf2PasswordHash newPBKDF2Encoder(
            int iterations, int saltSizeBytes,
            int keySizeBytes, Algorithm algorithm, SecureRandom random) {
        
        if (algorithm == null) algorithm = Algorithm.PBKDF2WithHmacSHA512;

        final PBKDF2WithHmacSHA pbkdf2 = new PBKDF2WithHmacSHA(algorithm.name(), iterations, 
                saltSizeBytes, keySizeBytes, random);

        return new BCryptPbkdf2PasswordHash(pbkdf2, pbkdf2, new BCryptPasswordEncoder());
    }

    /**
     * Creates a new instance using {@link Algorithm#BCrypt} to hash passwords.
     */
    public BCryptPbkdf2PasswordHash() {
        this(Algorithm.BCrypt);
    }

    /**
     * Creates a new {@link BCryptPbkdf2PasswordHash} using the {@link Algorithm} in the default config.
     * @param algorithm the {@link Algorithm} to use.
     */
    public BCryptPbkdf2PasswordHash(Algorithm algorithm) {
        bCryptPasswordEncoder = new BCryptPasswordEncoder();
        if (algorithm == Algorithm.BCrypt) {
            defaultHasher = bCryptPasswordEncoder;
            pbkdf2WithHmacSHA = new PBKDF2WithHmacSHA();
        } else {
            pbkdf2WithHmacSHA = new PBKDF2WithHmacSHA(algorithm.name());
            defaultHasher = pbkdf2WithHmacSHA;
        }
    }
    /**
     * Consider using the static factory methods. This constructor allows the init of this class.
     * @param defaultHasher
     * @param pbkdf2WithHmacSHA
     * @param bCryptPasswordEncoder
     */
    public BCryptPbkdf2PasswordHash(PasswordHasher defaultHasher, 
            PBKDF2WithHmacSHA pbkdf2WithHmacSHA,
            BCryptPasswordEncoder bCryptPasswordEncoder) {
        super();
        Objects.requireNonNull(defaultHasher, "defaultHasher should not be null");
        Objects.requireNonNull(pbkdf2WithHmacSHA, "pbkdf2WithHmacSHA should not be null");
        Objects.requireNonNull(bCryptPasswordEncoder, "bCryptPasswordEncoder should not be null");

        this.defaultHasher = defaultHasher;
        this.pbkdf2WithHmacSHA = pbkdf2WithHmacSHA;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    /**
     * Encodes the password using the {@link Algorithm} of the constructor.
     * 
     * {@inheritDoc}
     */
    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        }
        return defaultHasher.encode(rawPassword);
    }

    /**
     * Decodes the password based of the prefixed algorithm, using either PBKDF2xx or BCrypt.
     * 
     * {@inheritDoc}
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null && encodedPassword == null) return true;
        else if (rawPassword == null && encodedPassword != null) return false;
        else if (rawPassword != null && encodedPassword == null) return false;
        else if (rawPassword == null) return false;
        
        if (encodedPassword.startsWith("PBKDF2")) {
            return pbkdf2WithHmacSHA.matches(rawPassword, encodedPassword);
        } else {
            return bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
        }
    }
    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "[" + defaultHasher.toString() + "]";
    }
}
