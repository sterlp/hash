/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sterl.hash.bcrypt;

import java.security.SecureRandom;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.sterl.hash.PasswordHasher;

import lombok.AllArgsConstructor;
import lombok.Getter;


/**
 * Implementation of PasswordEncoder that uses the BCrypt strong hashing function. Clients
 * can optionally supply a "version" ($2a, $2b, $2y) and a "strength" (a.k.a. log rounds in BCrypt)
 * and a SecureRandom instance. The larger the strength parameter the more work will have to be done
 * (exponentially) to hash the passwords. The default value is 10.
 *
 * @author Dave Syer
 */
public class BCryptPasswordEncoder implements PasswordHasher {
    private Pattern BCRYPT_PATTERN = Pattern
            .compile("\\A\\$2(a|y|b)?\\$(\\d\\d)\\$[./0-9A-Za-z]{53}");
    private final Logger logger = Logger.getLogger(this.getClass().getSimpleName());

    private final int strength;
    private final BCryptVersion version;

    private final SecureRandom random;


    public BCryptPasswordEncoder() {
        this(-1);
    }

    /**
     * @param strength the log rounds to use, between 4 and 31
     */
    public BCryptPasswordEncoder(int strength) {
        this(strength, null);
    }

    /**
     * @param version the version of bcrypt, can be 2a,2b,2y
     */
    public BCryptPasswordEncoder(BCryptVersion version) {
        this(version, null);
    }

    /**
     * @param version the version of bcrypt, can be 2a,2b,2y
     * @param random  the secure random instance to use
     */
    public BCryptPasswordEncoder(BCryptVersion version, SecureRandom random) {
        this(version, -1, random);
    }

    /**
     * @param strength the log rounds to use, between 4 and 31
     * @param random   the secure random instance to use
     */
    public BCryptPasswordEncoder(int strength, SecureRandom random) {
        this(BCryptVersion.$2A, strength, random);
    }

    /**
     * @param version  the version of bcrypt, can be 2a,2b,2y
     * @param strength the log rounds to use, between 4 and 31
     */
    public BCryptPasswordEncoder(BCryptVersion version, int strength) {
        this(version, strength, null);
    }

    /**
     * @param version  the version of bcrypt, can be 2a,2b,2y
     * @param strength the log rounds to use, between 4 and 31
     * @param random   the secure random instance to use
     */
    public BCryptPasswordEncoder(BCryptVersion version, int strength, SecureRandom random) {
        if (strength != -1 && (strength < BCrypt.MIN_LOG_ROUNDS || strength > BCrypt.MAX_LOG_ROUNDS)) {
            throw new IllegalArgumentException("Bad strength :" + strength 
                    + " should be between " + BCrypt.MIN_LOG_ROUNDS + " and " + BCrypt.MAX_LOG_ROUNDS);
        }
        this.version = version;
        this.strength = strength == -1 ? 10 : strength;
        this.random = random;
    }

    /**
     * Encode the raw password. Generally, a good encoding algorithm applies a SHA-1 or
     * greater hash combined with an 8-byte or greater randomly generated salt.
     */
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        }

        String salt;
        if (random != null) {
            salt = BCrypt.gensalt(version.getVersion(), strength, random);
        } else {
            salt = BCrypt.gensalt(version.getVersion(), strength);
        }
        return BCrypt.hashpw(rawPassword.toString(), salt);
    }

    /**
     * Verify the encoded password obtained from storage matches the submitted raw
     * password after it too is encoded. Returns true if the passwords match, false if
     * they do not. The stored password itself is never decoded.
     *
     * @param rawPassword the raw password to encode and match
     * @param encodedPassword the encoded password from storage to compare with
     * @return true if the raw password, after encoding, matches the encoded password from
     * storage
     */
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword cannot be null");
        }

        if (encodedPassword == null || encodedPassword.length() == 0) {
            logger.warning("Empty encoded password");
            return false;
        }

        if (!BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
            throw new IllegalArgumentException("Encoded password does not look like BCrypt: " + encodedPassword);
        }

        return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
    }

    /**
     * Returns true if the encoded password should be encoded again for better security,
     * else false. The default implementation always returns false.
     * @param encodedPassword the encoded password to check
     * @return true if the encoded password should be encoded again for better security,
     * else false.
     */
    public boolean upgradeEncoding(String encodedPassword) {
        if (encodedPassword == null || encodedPassword.length() == 0) {
            logger.warning("Empty encoded password");
            return false;
        }

        Matcher matcher = BCRYPT_PATTERN.matcher(encodedPassword);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Encoded password does not look like BCrypt: " + encodedPassword);
        }
        else {
            int strength = Integer.parseInt(matcher.group(2));
            return strength < this.strength;
        }
    }

    /**
     * Stores the default bcrypt version for use in configuration.
     *
     * @author Lin Feng
     */
    @AllArgsConstructor
    public enum BCryptVersion {
        $2A("$2a"),
        $2Y("$2y"),
        $2B("$2b");

        @Getter
        private final String version;
    }
    
    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "(strength: " + strength + ")";
    }
}
