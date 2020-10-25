package org.sterl.hash;

/**
 * The {@link PasswordHasher} should encode the password in the following way:
 * <blockquote><pre>
{@code <algorithm>:<the hashed password including the salt>}
 * </pre></blockquote>
 * 
 * The <code>algorithm</code> is used to identify the implementation of the {@link PasswordHasher}.
 */
public interface PasswordHasher {

    /**
     * Encode the raw password using a hash algorithm and salt.
     * 
     * @param rawPassword the raw password to encode
     * @return the hashed / encoded password
     */
    String encode(CharSequence rawPassword);

    /**
     * Verify the encoded password the raw password after. 
     * Returns <code>true</code> if the passwords matches, 
     * <code>false</code> if they do not.
     *
     * @param rawPassword the raw password to encode and match
     * @param encodedPassword the encoded password from storage to compare with
     * @return <code>true</code> if the raw password matches the encoded one.
     */
    boolean matches(CharSequence rawPassword, String encodedPassword);
}
