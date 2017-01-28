package com.boris.reservations.zuul.security.token;

/**
 * The Class JwtTokenContainer.
 */
public class JwtTokenContainer {
	
	/** The access jwt token. */
	private String accessJwtToken;
	
	/** The refresh token. */
	private String refreshToken;
	
	/**
	 * Instantiates a new jwt token container.
	 *
	 * @param accessJwtToken the access jwt token
	 * @param refreshToken the refresh token
	 */
	public JwtTokenContainer(String accessJwtToken, String refreshToken) {
		this.accessJwtToken = accessJwtToken;
		this.refreshToken = refreshToken;
	}

	/**
	 * Gets the access jwt token.
	 *
	 * @return the access jwt token
	 */
	public String getAccessJwtToken() {
		return accessJwtToken;
	}

	/**
	 * Gets the refresh token.
	 *
	 * @return the refresh token
	 */
	public String getRefreshToken() {
		return refreshToken;
	}
	
}
