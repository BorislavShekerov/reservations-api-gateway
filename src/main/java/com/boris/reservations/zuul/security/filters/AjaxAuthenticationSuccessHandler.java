package com.boris.reservations.zuul.security.filters;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import com.boris.reservations.zuul.security.model.UserContext;
import com.boris.reservations.zuul.security.model.UserLoginResponse;
import com.boris.reservations.zuul.security.token.JwtToken;
import com.boris.reservations.zuul.security.token.JwtTokenContainer;
import com.boris.reservations.zuul.security.token.JwtTokenFactory;
import com.fasterxml.jackson.databind.ObjectMapper;


@Service
public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final ObjectMapper mapper;
	private final JwtTokenFactory tokenFactory;

	@Autowired
	public AjaxAuthenticationSuccessHandler(final ObjectMapper mapper, final JwtTokenFactory tokenFactory) {
		this.mapper = mapper;
		this.tokenFactory = tokenFactory;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		UserContext userContext = (UserContext) authentication.getPrincipal();

		JwtToken accessToken = tokenFactory.createAccessJwtToken(userContext);
		JwtToken refreshToken = tokenFactory.createRefreshToken(userContext);

		JwtTokenContainer jwtTokenContainer = new JwtTokenContainer(accessToken.getToken(), refreshToken.getToken());
		UserLoginResponse loginResponse = new UserLoginResponse((UserContext) authentication.getPrincipal(), jwtTokenContainer);
		
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		mapper.writeValue(response.getWriter(), loginResponse);
		
		
		clearAuthenticationAttributes(request);
	}

	/**
	 * Removes temporary authentication-related data which may have been stored
	 * in the session during the authentication process..
	 * 
	 */
	protected final void clearAuthenticationAttributes(HttpServletRequest request) {
		HttpSession session = request.getSession(false);

		if (session == null) {
			return;
		}

		session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}

}
