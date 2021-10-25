package com.kb.demo.jwt;

import static com.nimbusds.jose.JWSAlgorithm.RS256;

import java.net.MalformedURLException;
import java.net.URL;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

@Configuration
public class AwsCognitoJwtProcessorFactory {

	@Autowired
	private AwsCognitoJwtConfiguration jwtConfiguration;
	
	@Bean
	public ConfigurableJWTProcessor<SecurityContext> configurableJWTProcessor() throws MalformedURLException {

		ConfigurableJWTProcessor<SecurityContext> jwtProcessor= new DefaultJWTProcessor<SecurityContext>();
		
		ResourceRetriever resourceRetriever = new DefaultResourceRetriever(jwtConfiguration.getConnectionTimeout(), jwtConfiguration.getReadTimeout());
		URL jwkSetURL= new URL(jwtConfiguration.getJwkUrl()); //https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
		JWKSource<SecurityContext> keySource= new RemoteJWKSet<SecurityContext>(jwkSetURL, resourceRetriever);		
		JWSKeySelector<SecurityContext> keySelector= new JWSVerificationKeySelector<SecurityContext>(RS256, keySource);
		jwtProcessor.setJWSKeySelector(keySelector);
		
		return jwtProcessor;
		
	}

}
