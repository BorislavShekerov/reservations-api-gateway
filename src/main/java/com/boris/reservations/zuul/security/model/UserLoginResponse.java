package com.boris.reservations.zuul.security.model;

import com.boris.reservations.zuul.security.token.JwtTokenContainer;

// TODO: Auto-generated Javadoc
/**
 * The Class UserLoginResponse.
 */
public class UserLoginResponse {
	
	/** The user details. */
	private UserContext userDetails;
	
	/** The jwt tokens. */
	private JwtTokenContainer jwtTokens;
	
	/**
	 * Instantiates a new user login response.
	 */
	public UserLoginResponse() {
	}
	
	/**
	 * Instantiates a new user login response.
	 *
	 * @param userDetails the user details
	 * @param jwtTokens the jwt tokens
	 */
	public UserLoginResponse(UserContext userDetails, JwtTokenContainer jwtTokens) {
		this.userDetails = userDetails;
		this.jwtTokens = jwtTokens;
	}

	/**
	 * Gets the user details.
	 *
	 * @return the user details
	 */
	public UserContext getUserDetails() {
		return userDetails;
	}
	
	/**
	 * Gets the jwt tokens.
	 *
	 * @return the jwt tokens
	 */
	public JwtTokenContainer getJwtTokens() {
		return jwtTokens;
	}
	
	
}
