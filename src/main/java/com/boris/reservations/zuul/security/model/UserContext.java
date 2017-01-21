package com.boris.reservations.zuul.security.model;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;

public class UserContext {
    private final String email;
    private final List<GrantedAuthority> authorities;

    private UserContext(String email, List<GrantedAuthority> authorities) {
        this.email = email;
        this.authorities = authorities;
    }
    
    public static UserContext create(String email, List<GrantedAuthority> authorities) {
        if (StringUtils.isBlank(email)) throw new IllegalArgumentException("Email is blank: " + email);
        return new UserContext(email, authorities);
    }

    public String getEmail() {
        return email;
    }

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
