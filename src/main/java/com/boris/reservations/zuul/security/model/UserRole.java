package com.boris.reservations.zuul.security.model;

public enum UserRole {
	ADMIN, OWNER, MEMBER;
	
	public String authority() {
        return "ROLE_" + this.name();
    }
}
