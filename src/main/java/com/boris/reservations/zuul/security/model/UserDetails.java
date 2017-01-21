package com.boris.reservations.zuul.security.model;

import java.util.List;

public class UserDetails {
	
	private String userId;
	private String email;
	private String password;
	private List<UserRole> roles;
	
	public UserDetails() {
	}
	
	public UserDetails(String userId, String email, String password, List<UserRole> roles) {
		this.userId = userId;
		this.email = email;
		this.password = password;
		this.roles = roles;
	}
	
	public String getUserId() {
		return userId;
	}
	
	public String getEmail() {
		return email;
	}
	
	public String getPassword() {
		return password;
	}
	
	public List<UserRole> getRoles() {
		return roles;
	}
}
