package com.boris.reservations.zuul.security.model;

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;

public class UserContext {
    private final String email;
    private final String firstName;
    private final String lastName;
    
    private final List<GrantedAuthority> authorities;

    private UserContext(String email, String firstName, String lastName, List<GrantedAuthority> authorities) {
		this.email = email;
		this.firstName = firstName;
		this.lastName = lastName;
		this.authorities = authorities;
	}

	public static UserContext create(String email, String firstName, String lastName, List<GrantedAuthority> authorities) {
        if (StringUtils.isBlank(email) || StringUtils.isBlank(firstName) || StringUtils.isBlank(lastName)) throw new IllegalArgumentException("Email is blank: " + email);
        return new UserContext(email, firstName, lastName, authorities);
    }

    public String getEmail() {
        return email;
    }
    
    public String getFirstName() {
		return firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
