package com.boris.reservations.zuul.security.model;

import java.util.List;

/**
 * The Class UserDetails.
 */
public class UserDetails {
	
	/** The user id. */
	private String userId;
	
	/** The email. */
	private String email;
	
	/** The first name. */
	private String firstName;
	
	/** The last name. */
	private String lastName;
	
	/** The password. */
	private String password;
	
	/** The roles. */
	private List<UserRole> roles;
	
	/**
	 * Instantiates a new user details.
	 */
	public UserDetails() {
	}
	
	/**
	 * Instantiates a new user details.
	 *
	 * @param userId the user id
	 * @param email the email
	 * @param firstName the first name
	 * @param lastName the last name
	 * @param password the password
	 * @param roles the roles
	 */
	public UserDetails(String userId, String email, String firstName, String lastName, String password,
			List<UserRole> roles) {
		this.userId = userId;
		this.email = email;
		this.firstName = firstName;
		this.lastName = lastName;
		this.password = password;
		this.roles = roles;
	}
	
	/**
	 * Gets the first name.
	 *
	 * @return the first name
	 */
	public String getFirstName() {
		return firstName;
	}

	/**
	 * Gets the last name.
	 *
	 * @return the last name
	 */
	public String getLastName() {
		return lastName;
	}

	/**
	 * Gets the user id.
	 *
	 * @return the user id
	 */
	public String getUserId() {
		return userId;
	}
	
	/**
	 * Gets the email.
	 *
	 * @return the email
	 */
	public String getEmail() {
		return email;
	}
	
	/**
	 * Gets the password.
	 *
	 * @return the password
	 */
	public String getPassword() {
		return password;
	}
	
	/**
	 * Gets the roles.
	 *
	 * @return the roles
	 */
	public List<UserRole> getRoles() {
		return roles;
	}

	/**
	 * Encrypt password.
	 *
	 * @param encryptedPassword the encrypted password
	 */
	public void encryptPassword(String encryptedPassword) {
		this.password = encryptedPassword;
	}

	/**
	 * Sets the roles.
	 *
	 * @param roles the new roles
	 */
	public void setRoles(List<UserRole> roles) {
		this.roles = roles;
	}
	
}
