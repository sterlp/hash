package org.sterl.jee.hash;

import javax.security.enterprise.identitystore.PasswordHash;
import javax.security.enterprise.identitystore.Pbkdf2PasswordHash;

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
 * @see org.sterl.hash.Algorithm
 * @see org.sterl.hash.bcrypt.BCryptPasswordEncoder.BCryptVersion
 * @see org.sterl.hash.BCryptPbkdf2PasswordHash
 */
public interface BCryptAndPbkdf2PasswordHash extends PasswordHash {

}
