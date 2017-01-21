package com.boris.reservations.zuul.security.token;

import org.springframework.stereotype.Component;

@Component
public class TokenVerifierImpl implements TokenVerifier {
    @Override
    public boolean verify(String jti) {
        return true;
    }
}

