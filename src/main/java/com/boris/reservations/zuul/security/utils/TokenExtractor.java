package com.boris.reservations.zuul.security.utils;

public interface TokenExtractor {
    public String extract(String payload);
}
