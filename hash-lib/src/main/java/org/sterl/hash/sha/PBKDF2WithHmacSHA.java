package org.sterl.hash.sha;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.sterl.hash.PasswordHasher;

import lombok.Getter;
import lombok.Setter;

/**
 * Re-implementation of the Soteria Pbkdf2PasswordHashImpl to share it with other frameworks.
 * 
 * Use one of the following PBKDF2 algorithms:
 * <blockquote><pre>
PBKDF2WithHmacSHA224
PBKDF2WithHmacSHA256
PBKDF2WithHmacSHA384
PBKDF2WithHmacSHA512 -- default
 * </pre></blockquote>
 *
 * <p>
 * The encoded format produced is as follows:
 * <blockquote><pre>
{@code <algorithm>:<iterations>:<base64(salt)>:<base64(hash)>}
 * </pre></blockquote>
 * Where:
 * <ul>
 * <li><i>algorithm</i> -- the algorithm used to generate the hash
 * <li><i>iterations</i> -- the number of iterations used to generate the hash
 * <li><i>base64(salt)</i> -- the salt used to generate the hash, base64-encoded
 * <li><i>base64(hash)</i> -- the hash value, base64-encoded
 * </ul>
 * <p>
 * Because the algorithm and the parameters used to generate the hash are stored with the hash,
 * the built-in {@code PBKDF2WithHmacSHA} implementation can verify hashes generated using algorithm
 * and parameter values that differ from the currently configured values. This means the configuration
 * parameters can be changed without impacting the ability to verify existing password hashes.
 * <p>
 * (Password hashes generated using algorithms/parameters outside the range supported by
 * {@code PBKDF2WithHmacSHA} cannot be verified.)
 *
 * 
 * @see <a href="https://github.com/payara/patched-src-security-soteria/blob/master/impl/src/main/java/org/glassfish/soteria/identitystores/hash/Pbkdf2PasswordHashImpl.java">Pbkdf2PasswordHashImpl.java</a>
 */
@Getter @Setter
public class PBKDF2WithHmacSHA implements PasswordHasher {
    private final SecretKeyFactory configuredAlgorithm; // = "PBKDF2WithHmacSHA512";
    private final int configuredIterations; // = 2048;
    private final int configuredSaltSizeBytes; // = 32;
    private final int configuredKeySizeBytes; // = 32;
    private final SecureRandom random;
    private final String encodedPrefix;

    /**
     * Creates a new instance of {@link PBKDF2WithHmacSHA} it also adjust the constructor 
     * parameters if the min values aren't honored.
     * 
     * Algorithms:
     * <pre>
     * "PBKDF2WithHmacSHA224",
     * "PBKDF2WithHmacSHA256",
     * "PBKDF2WithHmacSHA384",
     * "PBKDF2WithHmacSHA512"
     * </pre>
     * 
     * @param algorithm default PBKDF2WithHmacSHA512
     * @param iterations basically the strength, default 2048
     * @param saltSizeBytes default 32
     * @param keySizeBytes default 64
     * @param random {@link SecureRandom} to generate the salt
     */
    public PBKDF2WithHmacSHA(String algorithm, int iterations, int saltSizeBytes,
            int keySizeBytes, SecureRandom random) {
        // enforce some min values
        if (iterations < 1024) iterations = 1024;
        if (saltSizeBytes < 16) saltSizeBytes = 16;
        if (keySizeBytes < 16) keySizeBytes = 16;
        if (algorithm == null) algorithm = "PBKDF2WithHmacSHA512";

        this.configuredAlgorithm = getAlgorithm(algorithm);
        this.configuredIterations = iterations;
        this.configuredSaltSizeBytes = saltSizeBytes;
        this.configuredKeySizeBytes = keySizeBytes;
        this.random = random == null ? new SecureRandom() : random;

        this.encodedPrefix = algorithm + ":" + configuredIterations + ":";
    }
    
    /**
     * Creates a new instance using PBKDF2WithHmacSHA512.
     * 
     * @see #PBKDF2WithHmacSHA(String, int, int, int, SecureRandom)
     */
    public PBKDF2WithHmacSHA() {
        this("PBKDF2WithHmacSHA512");
    }

    /**
     * Creates a new instance wit the given algorithm and 2048 iterations and 32 for salt and 64 key size.
     * @param algorithm e.g. PBKDF2WithHmacSHA512 | PBKDF2WithHmacSHA384 | PBKDF2WithHmacSHA256
     */
    public PBKDF2WithHmacSHA(String algorithm) {
        this(algorithm, 2048, 32, 64, new SecureRandom());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String encode(CharSequence rawPassword) {
        return encode(rawPassword.toString().toCharArray());
    }

    /**
     * Hashes the given password using PBKDF2.
     * 
     * @param password the password to encode, not <code>null</code>
     * @return the encoded password, never <code>null</code>
     * 
     * @see #encode(CharSequence) 
     */
    public String encode(char[] password) {
        final byte[] salt = new byte[configuredSaltSizeBytes];
        random.nextBytes(salt);
        final byte[] hash = pbkdf2(password, salt, configuredAlgorithm, configuredIterations, configuredKeySizeBytes);
        final Encoder encoder = Base64.getEncoder();
        return encodedPrefix +
                encoder.encodeToString(salt) 
                + ":" +
                encoder.encodeToString(hash);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return matches(rawPassword.toString().toCharArray(), encodedPassword);
    }
    /**
     * Check the given password against the given hash.
     * 
     * @param password the entered password
     * @param hashedPassword the stored password hash to compare
     * @return <code>true</code> if matches, otherwise <code>false</code>
     * 
     * @see #matches(CharSequence, String)
     */
    public boolean matches(char[] password, String hashedPassword) {
        final String[] tokens = hashedPassword.split(":");
        if (tokens.length != 4) {
            throw new IllegalArgumentException("Bad hash encoding, expected 4 tokens split by '.' but found " 
                    + tokens.length + " in " + hashedPassword);
        }

        final SecretKeyFactory algorithm = getAlgorithm(tokens[0]);
        int iterations;
        byte[] salt;
        byte[] hash;
        try {
            iterations = Integer.parseInt(tokens[1]);
            salt = Base64.getDecoder().decode(tokens[2]);
            hash = Base64.getDecoder().decode(tokens[3]);
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad hash encoding of " + hashedPassword, e);
        }
        
        byte[] hashToVerify = pbkdf2(
                password,
                salt,
                algorithm,
                iterations,
                hash.length);

        return MessageDigest.isEqual(hashToVerify, hash);
    }

    private byte[] pbkdf2(char[] password, byte[] salt, SecretKeyFactory algorithm, int iterations, int keySizeBytes) {
        try {
            return algorithm.generateSecret(
                    new PBEKeySpec(password, salt, iterations, keySizeBytes * 8)).getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    private SecretKeyFactory getAlgorithm(String algorithm) {
        try {
            return SecretKeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Algorithm '" + algorithm + "' not found.", e);
        }
    }
    
    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "(" + encodedPrefix + configuredSaltSizeBytes
                + ":" + configuredKeySizeBytes + ")";
    }
}
