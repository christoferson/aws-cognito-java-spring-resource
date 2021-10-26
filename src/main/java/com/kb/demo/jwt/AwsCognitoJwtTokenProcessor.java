package com.kb.demo.jwt;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;

@Component
public class AwsCognitoJwtTokenProcessor {
	
	private static final Log LOGGER = LogFactory.getLog(AwsCognitoJwtTokenProcessor.class);

    @Autowired
    private AwsCognitoJwtConfiguration jwtConfiguration;

    @Autowired
    private ConfigurableJWTProcessor<SecurityContext> configurableJWTProcessor;

    public Authentication authenticate(HttpServletRequest request) throws Exception {

        String httpAuthorizationHeaderName = jwtConfiguration.getHttpAuthorizationHeaderName();
		String jwtTokenAuthorizationHeader = request.getHeader(httpAuthorizationHeaderName);
        if (jwtTokenAuthorizationHeader == null) {
        	LOGGER.warn(String.format("Failed to retrieve Authorization Header. %s", httpAuthorizationHeaderName));
        	return null;
        }
        
        String jwtBearerToken = this.getBearerToken(jwtTokenAuthorizationHeader);
		JWTClaimsSet claims = this.configurableJWTProcessor.process(jwtBearerToken, null);
        printClaims(claims);
        verifyIssuer(claims);
        verifyToken(claims);
        String username = getUserNameFrom(claims);
        if (username == null) {
        	LOGGER.warn(String.format("Failed to retrieve UserName from JWT Token."));
        	return null;
        }

        List<GrantedAuthority> grantedAuthorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
        User user = new User(username, "", List.of());
        return new AwsCognitoJwtToken(user, claims, grantedAuthorities);
        
    }

    private String getUserNameFrom(JWTClaimsSet claims) {
        String userNameField = this.jwtConfiguration.getUserNameField();
		Object userName = claims.getClaims().get(userNameField);
		if (userName == null) {
			throw new RuntimeException("Unable to get username. Field=" + userNameField);
		}
		return userName.toString();
    }

    private void verifyToken(JWTClaimsSet claims) {
        Object claimTokenUse = claims.getClaim("token_use");
		if (!Objects.equals(claimTokenUse, "access")) {
            throw new RuntimeException("JWT Token is not an Access Token");
        }
    }

    private void verifyIssuer(JWTClaimsSet claims) {
        String cognitoIssuer = jwtConfiguration.getCognitoIdentityPoolUrl();
		if (!claims.getIssuer().equals(cognitoIssuer)) {
            throw new RuntimeException(String.format("Issuer %s does not match cognito idp %s", claims.getIssuer(), cognitoIssuer));
        }
    }

    private String getBearerToken(String token) {
        return token.startsWith("Bearer ") ? token.substring("Bearer ".length()) : token;
    }
    
    private void printClaims(JWTClaimsSet claims) {

    	Map<String, Object> claimsMap = claims.getClaims();
		for (String key : claimsMap.keySet()) {
			var val = claimsMap.get(key);
			System.out.println(String.format("     %s = %s", key, val));
    	}
    	
    }
}
