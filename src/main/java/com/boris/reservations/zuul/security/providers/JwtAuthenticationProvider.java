package com.boris.reservations.zuul.security.providers;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.boris.reservations.zuul.security.config.JwtSettings;
import com.boris.reservations.zuul.security.model.UserContext;
import com.boris.reservations.zuul.security.token.JwtAuthenticationToken;
import com.boris.reservations.zuul.security.token.RawAccessJwtToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * The Class JwtAuthenticationProvider.
 */
@Component
@SuppressWarnings("unchecked")
public class JwtAuthenticationProvider implements AuthenticationProvider {
    
    /** The jwt settings. */
    private final JwtSettings jwtSettings;
    
    /**
     * Instantiates a new jwt authentication provider.
     *
     * @param jwtSettings the jwt settings
     */
    @Autowired
    public JwtAuthenticationProvider(JwtSettings jwtSettings) {
        this.jwtSettings = jwtSettings;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.authentication.AuthenticationProvider#authenticate(org.springframework.security.core.Authentication)
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    	RawAccessJwtToken rawAccessToken = (RawAccessJwtToken) authentication.getCredentials();
    	
        Jws<Claims> jwsClaims = rawAccessToken.parseClaims(jwtSettings.getTokenSigningKey());
        Claims claimsBody = jwsClaims.getBody();
        
        String subject = claimsBody.getSubject();
        List<String> scopes = claimsBody.get("scopes", List.class);
        String firstName = claimsBody.get("firstName", String.class);
        String lastName = claimsBody.get("lastName", String.class);
        
        List<GrantedAuthority> authorities = scopes.stream()
                .map(authority -> new SimpleGrantedAuthority(authority))
                .collect(Collectors.toList());
        
        UserContext context = UserContext.create(subject, firstName, lastName, authorities);
        
        return new JwtAuthenticationToken(context, context.getAuthorities());
    }

    /* (non-Javadoc)
     * @see org.springframework.security.authentication.AuthenticationProvider#supports(java.lang.Class)
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
