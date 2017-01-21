package com.boris.reservations.zuul.security.endpoints;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.boris.reservations.zuul.security.config.JwtSettings;
import com.boris.reservations.zuul.security.config.WebSecurityConfig;
import com.boris.reservations.zuul.security.exceptions.InvalidJwtToken;
import com.boris.reservations.zuul.security.model.UserContext;
import com.boris.reservations.zuul.security.model.UserDetails;
import com.boris.reservations.zuul.security.service.UserService;
import com.boris.reservations.zuul.security.token.JwtToken;
import com.boris.reservations.zuul.security.token.JwtTokenFactory;
import com.boris.reservations.zuul.security.token.RawAccessJwtToken;
import com.boris.reservations.zuul.security.token.RefreshToken;
import com.boris.reservations.zuul.security.token.TokenVerifier;
import com.boris.reservations.zuul.security.utils.TokenExtractor;

@RestController
public class RefreshTokenEndpoint {
    @Autowired private JwtTokenFactory tokenFactory;
    @Autowired private JwtSettings jwtSettings;
    @Autowired private UserService userService;
    @Autowired private TokenVerifier tokenVerifier;
    @Autowired @Qualifier("jwtHeaderTokenExtractor") private TokenExtractor tokenExtractor;
    
    @RequestMapping(value="/api/auth/token", method=RequestMethod.GET, produces={ MediaType.APPLICATION_JSON_VALUE })
    public @ResponseBody JwtToken refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String tokenPayload = tokenExtractor.extract(request.getHeader(WebSecurityConfig.JWT_TOKEN_HEADER_PARAM));
        
        RawAccessJwtToken rawToken = new RawAccessJwtToken(tokenPayload);
        RefreshToken refreshToken = RefreshToken.create(rawToken, jwtSettings.getTokenSigningKey()).orElseThrow(() -> new InvalidJwtToken());

        String jti = refreshToken.getJti();
        if (!tokenVerifier.verify(jti)) {
            throw new InvalidJwtToken();
        }

        String subject = refreshToken.getSubject();
        UserDetails user = userService.getUserDetails(subject);
        if(user == null) throw new UsernameNotFoundException("User not found: " + subject);

        if (user.getRoles() == null) throw new InsufficientAuthenticationException("User has no roles assigned");
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.authority()))
                .collect(Collectors.toList());

        UserContext userContext = UserContext.create(user.getEmail(), authorities);

        return tokenFactory.createAccessJwtToken(userContext);
    }
}
