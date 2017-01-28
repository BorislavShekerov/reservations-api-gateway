package com.boris.reservations.zuul.security.token;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.security.authentication.BadCredentialsException;

import com.boris.reservations.zuul.security.filters.JwtExpiredTokenException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * The Class RefreshToken.
 */
@SuppressWarnings("unchecked")
public class RefreshToken implements JwtToken {

	/** The raw token. */
	private String rawToken;

	/** The claims. */
	private Jws<Claims> claims;

	/**
	 * Instantiates a new refresh token.
	 *
	 * @param rawToken
	 *            the raw token
	 * @param claims
	 *            the claims
	 */
	public RefreshToken(String rawToken, Jws<Claims> claims) {
		this.rawToken = rawToken;
		this.claims = claims;
	}

	/**
	 * Creates and validates Refresh token.
	 *
	 * @param token
	 *            the token
	 * @param signingKey
	 *            the signing key
	 * @return the optional
	 * @throws BadCredentialsException
	 *             the bad credentials exception
	 * @throws JwtExpiredTokenException
	 *             the jwt expired token exception
	 */
	public static Optional<RefreshToken> create(RawAccessJwtToken token, String signingKey) {
		Jws<Claims> claims = token.parseClaims(signingKey);

		List<String> scopes = claims.getBody().get("scopes", List.class);
		if (scopes == null || scopes.isEmpty() || !scopes.stream()
				.filter(scope -> Scopes.REFRESH_TOKEN.authority().equals(scope)).findFirst().isPresent()) {
			return Optional.empty();
		}

		return Optional.of(new RefreshToken(token.getToken(), claims));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.boris.reservations.zuul.security.token.JwtToken#getToken()
	 */
	@Override
	public String getToken() {
		return rawToken;
	}

	/**
	 * Gets the claims.
	 *
	 * @return the claims
	 */
	public Jws<Claims> getClaims() {
		return claims;
	}

	/**
	 * Gets the jti.
	 *
	 * @return the jti
	 */
	public String getJti() {
		return claims.getBody().getId();
	}

	/**
	 * Gets the subject.
	 *
	 * @return the subject
	 */
	public String getSubject() {
		return claims.getBody().getSubject();
	}

	/**
	 * Extend lifetime.
	 *
	 * @param extension
	 *            the extension
	 */
	public void extendLifetime(int extension) {
		Claims refreshedClaims = Jwts.claims().setSubject(claims.getBody().getSubject());
		refreshedClaims.put("scopes", Arrays.asList(Scopes.REFRESH_TOKEN.authority()));

		Instant currentExpiration = claims.getBody().getExpiration().toInstant();

		this.rawToken = Jwts.builder().setClaims(refreshedClaims).setIssuer(claims.getBody().getIssuer())
				.setId(claims.getBody().getId()).setIssuedAt(claims.getBody().getIssuedAt())
				.setExpiration(Date.from(currentExpiration.plus(extension, ChronoUnit.MINUTES)))
				.signWith(SignatureAlgorithm.HS512, claims.getSignature()).compact();
	}
}
