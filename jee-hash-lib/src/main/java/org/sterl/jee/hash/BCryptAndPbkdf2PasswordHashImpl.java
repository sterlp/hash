package org.sterl.jee.hash;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.security.enterprise.identitystore.Pbkdf2PasswordHash;

import org.sterl.hash.Algorithm;
import org.sterl.hash.BCryptPbkdf2PasswordHash;
import org.sterl.hash.bcrypt.BCryptPasswordEncoder.BCryptVersion;

import lombok.Getter;

/**
 * Supports the {@link Pbkdf2PasswordHash} and the Spring Boot BCrypt.
 * 
 * <h2>Supported Algorithms Parameters:</h2>
 * <b>Algorithm</b>
 * <ul>
 *  <li>PBKDF2WithHmacSHA224</li>
 *  <li>PBKDF2WithHmacSHA256</li>
 *  <li>PBKDF2WithHmacSHA384</li>
 *  <li>PBKDF2WithHmacSHA512</li>
 *  <li>BCrypt</li>
 * </ul>
 * 
 * <p>
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
 * </p>
 * <p>
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
 * </p>
 * @see Algorithm
 * @see BCryptVersion
 * @see BCryptPbkdf2PasswordHash
 */
@ApplicationScoped
@Getter
public class BCryptAndPbkdf2PasswordHashImpl implements BCryptAndPbkdf2PasswordHash {
    private static final Logger LOGGER = Logger.getLogger(BCryptAndPbkdf2PasswordHashImpl.class.getSimpleName());
    /**
     * <h2>Supported Algorithms:</h2>
     * <ul>
     *  <li>PBKDF2WithHmacSHA224</li>
     *  <li>PBKDF2WithHmacSHA256</li>
     *  <li>PBKDF2WithHmacSHA384</li>
     *  <li>PBKDF2WithHmacSHA512</li>
     *  <li>BCrypt</li>
     * </ul>
     */
    public static final String ALGORITHM = "Algorithm";

    /**
     * <li><b>Pbkdf2PasswordHash.Iterations</b>
     *      <ul>
     *          <li>min 1024</li>
     *          <li>default 2048</li>
     *      </ul>
     *  </li>
     */
    public static final String PBKDF2_ITERATIONS = "Pbkdf2PasswordHash.Iterations";

    /**
     * <li><b>Pbkdf2PasswordHash.SaltSizeBytes</b>
     *      <ul>
     *          <li>min 16</li>
     *          <li>default 32</li>
     *      </ul>
     *  </li>
     */
    public static final String PBKDF2_SALTSIZE = "Pbkdf2PasswordHash.SaltSizeBytes";

    /**
     * <li><b>Pbkdf2PasswordHash.KeySizeBytes</b>
     *      <ul>
     *          <li>min 16</li>
     *          <li>default 32</li>
     *      </ul>
     *  </li>
     */
    public static final String PBKDF2_KEYSIZE = "Pbkdf2PasswordHash.KeySizeBytes";

    /**
     * <li><b>BCrypt.Version</b>
     *      <ul>
     *          <li>$2A</li>
     *          <li>$2Y</li>
     *          <li>$2B</li>
     *      </ul>
     * </li>
     */
    public static final String BCRYPT_VERSION = "BCrypt.Version";

    /**
     * <li><b>BCrypt.Strength</b>
     *      <ul>
     *          <li>min 4</li>
     *          <li>max 31</li>
     *      </ul>
     * </li>
     */
    public static final String BCRYPT_STRENGTH = "BCrypt.Strength";
    
    private BCryptPbkdf2PasswordHash encoder = new BCryptPbkdf2PasswordHash();
    
    private Algorithm algorithm = Algorithm.BCrypt;
    private int pbkdf2Iterations = 32;
    private int pbkdf2SaltSizeBytes = 32;
    private int pbkdf2KeySizeBytes = 32;
    
    private int bCryptStrength = BCryptPbkdf2PasswordHash.DEFAULT_BCRYPT_STRENGTH;
    private BCryptVersion bCryptVersion = BCryptPbkdf2PasswordHash.DEFAULT_VERSION;

    @Override
    public void initialize(Map<String, String> parameters) {
        Map<String, String> params = new HashMap<>();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            if (entry.getKey().endsWith(ALGORITHM)) {
                algorithm = Algorithm.valueOf(entry.getValue());
            } else {
                params.put(entry.getKey(), entry.getValue());
            }
        }
        
        if (algorithm == Algorithm.BCrypt) initBCrypt(params);
        else initPbkdf2(algorithm, params);
        
        LOGGER.info("initialized: " + encoder);
    }

    private void initBCrypt(Map<String, String> parameters) {
        for (Entry<String, String> entry : parameters.entrySet()) {
            if (BCRYPT_STRENGTH.equalsIgnoreCase(entry.getKey())) {
                bCryptStrength = parseInt(entry.getValue(), BCRYPT_STRENGTH, 4);
            } else if (BCRYPT_VERSION.equalsIgnoreCase(entry.getKey())) {
                bCryptVersion = BCryptVersion.valueOf(entry.getValue());
            } else {
                throw new IllegalArgumentException("Unrecognized parameter '" + entry.getKey() 
                    + "' for BCryptPasswordEncoder. Supported is: " + BCRYPT_STRENGTH
                    + ", " + BCRYPT_VERSION);
            }
            
        }
        this.encoder = BCryptPbkdf2PasswordHash.newBCryptPasswordEncoder(
                bCryptStrength, bCryptVersion, null);
    }
    private void initPbkdf2(Algorithm algorithm, Map<String, String> parameters) {
        for (Entry<String, String> entry : parameters.entrySet()) {
            if (PBKDF2_ITERATIONS.equalsIgnoreCase(entry.getKey())) {
                pbkdf2Iterations = parseInt(entry.getValue(), PBKDF2_ITERATIONS, 16);
            } else if (entry.getKey().equals(PBKDF2_SALTSIZE)) {
                pbkdf2SaltSizeBytes = parseInt(entry.getValue(), PBKDF2_SALTSIZE, 16);
            }
            else if (entry.getKey().equals(PBKDF2_KEYSIZE)) {
                pbkdf2KeySizeBytes = parseInt(entry.getValue(), PBKDF2_KEYSIZE, 16);
            } else {
                throw new IllegalArgumentException("Unrecognized parameter '" + entry.getKey() + "' for Pbkdf2PasswordHash");
            }
        }
        this.encoder = BCryptPbkdf2PasswordHash.newPBKDF2Encoder(pbkdf2Iterations, pbkdf2SaltSizeBytes, 
                pbkdf2KeySizeBytes, algorithm, null);
    }
    
    private static final int parseInt(String value, String what, int minValue) {
        int result;
        try {
            result = Integer.parseInt(value);
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad " + what + " parameter: " + value);
        }
        if (result < minValue) {
            throw new IllegalArgumentException(what + " min value is " + minValue + " but got: " + result);
        }
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String generate(char[] password) {
        if (password == null) return null;
        return this.encoder.encode(String.valueOf(password));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(char[] rawPassword, String encodedPassword) {
        if (rawPassword == null && encodedPassword == null) return true;
        else if (rawPassword == null && encodedPassword != null) return false;
        else if (rawPassword != null && encodedPassword == null) return false;
        else if (rawPassword == null) return false;

        return this.encoder.matches(String.valueOf(rawPassword), encodedPassword);
    }
}
