package com.boris.reservations.zuul.security.token;

public interface TokenVerifier {
    public boolean verify(String jti);
}
