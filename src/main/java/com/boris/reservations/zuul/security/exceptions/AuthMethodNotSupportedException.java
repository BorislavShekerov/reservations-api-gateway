package com.boris.reservations.zuul.security.exceptions;

import org.springframework.security.core.AuthenticationException;

public class AuthMethodNotSupportedException extends AuthenticationException {
	private static final long serialVersionUID = 954323325829814443L;

	public AuthMethodNotSupportedException(String msg) {
        super(msg);
    }
}
