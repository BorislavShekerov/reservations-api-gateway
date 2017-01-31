package com.boris.reservations.zuul.security.providers;

import static java.util.stream.Collectors.toList;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.boris.reservations.zuul.security.model.UserContext;
import com.boris.reservations.zuul.security.model.UserDetails;
import com.boris.reservations.zuul.security.service.UserService;

/**
 * The Class AjaxAuthenticationProvider.
 *
 * @author sheke
 */
@Component
public class AjaxAuthenticationProvider implements AuthenticationProvider {
    
    /** The encoder. */
    private final BCryptPasswordEncoder encoder;
    
    /** The user service. */
    @Autowired
    private final UserService userService;

    
    /**
     * Instantiates a new ajax authentication provider.
     *
     * @param userService the user service
     * @param encoder the encoder
     */
    public AjaxAuthenticationProvider(final UserService userService, final BCryptPasswordEncoder encoder) {
        this.userService = userService;
        this.encoder = encoder;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.authentication.AuthenticationProvider#authenticate(org.springframework.security.core.Authentication)
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        UserDetails user = userService.getUserDetails(username);
        
        if(user == null) throw new UsernameNotFoundException("User not found: " + username);
        
        encoder.encode(password);
        if (!encoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Authentication Failed. Username or Password not valid.");
        }

        if (user.getRoles() == null) throw new InsufficientAuthenticationException("User has no roles assigned");
        
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.authority()))
                .collect(toList());
        
        UserContext userContext = UserContext.create(user.getEmail(), user.getFirstName(), user.getLastName(), authorities);
        
        return new UsernamePasswordAuthenticationToken(userContext, null, userContext.getAuthorities());
    }

    /* (non-Javadoc)
     * @see org.springframework.security.authentication.AuthenticationProvider#supports(java.lang.Class)
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
