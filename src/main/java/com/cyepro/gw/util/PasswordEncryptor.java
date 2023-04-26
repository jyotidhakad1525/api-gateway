package com.cyepro.gw.util;

import org.springframework.security.crypto.bcrypt.BCrypt;

public final class PasswordEncryptor {

	private PasswordEncryptor() {
	}

	public static final int NUMBER_12 = 12;

	/**
	 * Hash a {@link java.lang.String}
	 * 
	 * @param value the value to hash
	 * @return the hashed value
	 */
	public static String encrypt(final String value) {
		return BCrypt.hashpw(value, BCrypt.gensalt(NUMBER_12));
	}

	/**
	 * Check that a plaintext password value a previously hashed one
	 * 
	 * @param value  the plaintext value to verify
	 * @param hashed the previously-hashed value
	 * @return true if the values match, false otherwise
	 */
	public static boolean check(final String value, final String hashed) {
		return BCrypt.checkpw(value, hashed);
	}
	
	public static void main(String[] args) {
		System.out.println(PasswordEncryptor.encrypt("Master@123"));
	}
}