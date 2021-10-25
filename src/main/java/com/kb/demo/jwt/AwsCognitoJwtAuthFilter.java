package com.kb.demo.jwt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Objects;

@Component
public class AwsCognitoJwtAuthFilter extends GenericFilter {

	private static final long serialVersionUID = 1L;

	private static final Log logger = LogFactory.getLog(AwsCognitoJwtAuthFilter.class);
    
	private AwsCognitoJwtTokenProcessor cognitoIdTokenProcessor;

    public AwsCognitoJwtAuthFilter(AwsCognitoJwtTokenProcessor cognitoIdTokenProcessor) {
    	Objects.requireNonNull(cognitoIdTokenProcessor);
        this.cognitoIdTokenProcessor = cognitoIdTokenProcessor;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        Authentication authentication;

        try {
            authentication = cognitoIdTokenProcessor.authenticate((HttpServletRequest) request);
            if (authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Cognito ID Token processing error", ex);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}

