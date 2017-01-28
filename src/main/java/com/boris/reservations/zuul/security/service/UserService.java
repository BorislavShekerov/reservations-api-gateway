package com.boris.reservations.zuul.security.service;

import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.boris.reservations.zuul.security.model.UserDetails;

@Service
@FeignClient("user-service")
public interface UserService {
	
	@RequestMapping(method = RequestMethod.GET, value = "/users/{userEmail}")
	public UserDetails getUserDetails(@PathVariable("userEmail") String userEmail);

	@RequestMapping(method = RequestMethod.POST, value = "/users/")
	public Boolean registerUserDetails(UserDetails userDetailsToRegister);
}
