
package com.cards.auth.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public final class CustomBcryptPasswordEncoder {

	private static BCryptPasswordEncoder bCryptPasswordEncoder;
	
	private CustomBcryptPasswordEncoder() {
		
	}
	
	public static synchronized BCryptPasswordEncoder getBcryptPasswordEncoder() {
		if(bCryptPasswordEncoder == null) {
			bCryptPasswordEncoder = new BCryptPasswordEncoder();
		}
		return bCryptPasswordEncoder;
	}
}
