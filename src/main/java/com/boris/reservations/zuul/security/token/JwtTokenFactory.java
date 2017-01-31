package com.boris.reservations.zuul.security.token;

import static java.util.stream.Collectors.toList;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.boris.reservations.zuul.security.config.JwtSettings;
import com.boris.reservations.zuul.security.model.UserContext;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenFactory {
	
    private final JwtSettings settings;

    @Autowired
    public JwtTokenFactory(JwtSettings settings) {
        this.settings = settings;
    }

    /**
     * Factory method for issuing new JWT Tokens.
     * 
     * @param username
     * @param roles
     * @return
     */
    public AccessJwtToken createAccessJwtToken(UserContext userContext) {
        if (StringUtils.isBlank(userContext.getEmail())) 
            throw new IllegalArgumentException("Cannot create JWT Token without email");

        if (userContext.getAuthorities() == null || userContext.getAuthorities().isEmpty()) 
            throw new IllegalArgumentException("User doesn't have any privileges");

        Claims claims = Jwts.claims().setSubject(userContext.getEmail());
        claims.put("firstName", userContext.getFirstName());
        claims.put("lastName", userContext.getFirstName());
        claims.put("scopes", userContext.getAuthorities().stream().map(s -> s.toString()).collect(toList()));

        Instant currentTime = Instant.now();

		String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(settings.getTokenIssuer())
          .setIssuedAt(Date.from(currentTime))
          .setExpiration(Date.from(currentTime.plus(settings.getTokenExpirationTime(), ChronoUnit.MINUTES)))
          .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
        .compact();

        return new AccessJwtToken(token, claims);
    }

    public JwtToken createRefreshToken(UserContext userContext) {
        if (StringUtils.isBlank(userContext.getEmail())) {
            throw new IllegalArgumentException("Cannot create JWT Token without username");
        }

        Instant currentTime = Instant.now();

        Claims claims = Jwts.claims().setSubject(userContext.getEmail());
        claims.put("scopes", Arrays.asList(Scopes.REFRESH_TOKEN.authority()));
        
        String token = Jwts.builder()
          .setClaims(claims)
          .setIssuer(settings.getTokenIssuer())
          .setId(UUID.randomUUID().toString())
          .setIssuedAt(Date.from(currentTime))
          .setExpiration(Date.from(currentTime.plus(settings.getRefreshTokenExpTime(), ChronoUnit.MINUTES)))
          .signWith(SignatureAlgorithm.HS512, settings.getTokenSigningKey())
        .compact();

        return new AccessJwtToken(token, claims);
    }
}
