package com.boris.reservations.zuul.security.endpoints;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.boris.reservations.zuul.security.model.UserContext;
import com.boris.reservations.zuul.security.model.UserDetails;
import com.boris.reservations.zuul.security.model.UserRole;
import com.boris.reservations.zuul.security.service.UserService;
import com.boris.reservations.zuul.security.token.JwtToken;
import com.boris.reservations.zuul.security.token.JwtTokenFactory;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The Class RestRegistrationEndpoint.
 *
 * @author sheke
 */
@Controller
public class RestRegistrationEndpoint {

	/** The Constant LOGGER. */
	private static final Logger LOGGER = Logger.getLogger(RestRegistrationEndpoint.class);
	
	/** The user service. */
	@Autowired
	private UserService userService;

	/** The mapper. */
	@Autowired
	private ObjectMapper mapper;

	/** The token factory. */
	@Autowired
	private JwtTokenFactory tokenFactory;

	/** The encoder. */
	@Autowired
	private BCryptPasswordEncoder encoder;

	/**
	 * Sign up.
	 *
	 * @param userToSignUp the user to sign up
	 * @param request the request
	 * @param response the response
	 * @return the response entity
	 * @throws JsonGenerationException the json generation exception
	 * @throws JsonMappingException the json mapping exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	@PostMapping("/api/auth/signUp")
	public ResponseEntity<?> signUp(@RequestBody UserDetails userToSignUp, HttpServletRequest request,
			HttpServletResponse response) throws JsonGenerationException, JsonMappingException, IOException {
		encodePassword(userToSignUp);
		userToSignUp.setRoles(Arrays.asList(UserRole.MEMBER));

		boolean emailFree = userService.registerUserDetails(userToSignUp);

		if (emailFree) {
			List<GrantedAuthority> authorities = userToSignUp.getRoles().stream()
					.map(authority -> new SimpleGrantedAuthority(authority.authority())).collect(Collectors.toList());

			UserContext userContext = UserContext.create(userToSignUp.getEmail(), userToSignUp.getFirstName(),
					userToSignUp.getLastName(), authorities);

			JwtToken accessToken = tokenFactory.createAccessJwtToken(userContext);
			JwtToken refreshToken = tokenFactory.createRefreshToken(userContext);

			Map<String, String> tokenMap = new HashMap<String, String>();
			tokenMap.put("token", accessToken.getToken());
			tokenMap.put("refreshToken", refreshToken.getToken());

			response.setStatus(HttpStatus.OK.value());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			mapper.writeValue(response.getWriter(), tokenMap);

			return new ResponseEntity<>(HttpStatus.CREATED);
		} else {
			return new ResponseEntity<>(HttpStatus.CONFLICT);
		}
	}

	/**
	 * Encode password.
	 *
	 * @param userToSignUp the user to sign up
	 */
	private void encodePassword(UserDetails userToSignUp) {
		userToSignUp.encryptPassword(encoder.encode(userToSignUp.getPassword()));
	}
}
