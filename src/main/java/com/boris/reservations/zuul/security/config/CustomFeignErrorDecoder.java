package com.boris.reservations.zuul.security.config;

import com.boris.reservations.zuul.security.exceptions.UserNameTakenException;

import feign.Response;
import feign.codec.ErrorDecoder;

public class CustomFeignErrorDecoder implements ErrorDecoder {
	
	private final ErrorDecoder defaultErrorDecoder = new Default();
	
	@Override
	public Exception decode(String methodKey, Response response) {
		 if (response.status() >= 400 && response.status() <= 499) {
	            return new UserNameTakenException();
	        }
	    
		 return defaultErrorDecoder.decode(methodKey, response);
	}

}
