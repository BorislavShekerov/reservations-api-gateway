package com.boris.reservations.zuul.security.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationServiceException;

public class JwtCookieTokenExtractor implements TokenExtractor {

	@Override
	public String extract(String payload) {
		if (StringUtils.isBlank(payload)) {
			throw new AuthenticationServiceException("Authorization header cannot be blank!");
		}
		
		String decodedCookie = null;
		try {
			decodedCookie = URLDecoder.decode(payload, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new AuthenticationServiceException("Decoding token cookie failed", e);
		}
		
		return decodedCookie;
	}

}
