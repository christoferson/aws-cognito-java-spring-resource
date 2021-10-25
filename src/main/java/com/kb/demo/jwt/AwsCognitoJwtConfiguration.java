package com.kb.demo.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(
        prefix = "com.kb.jwt.aws"
)
public class AwsCognitoJwtConfiguration {
    private String userPoolId;
    // JSON Web Key URL
    private String jwkUrl;
    private String region = "us-east-2";
    private String userNameField = "username"; //  //"cognito:username"
    private int connectionTimeout = 2000;
    private int readTimeout = 2000;
    private String httpAuthorizationHeaderName = "Authorization";

    public AwsCognitoJwtConfiguration() {
    }

    public String getJwkUrl() {
        return this.jwkUrl != null && !this.jwkUrl.isEmpty() ? this.jwkUrl : String.format("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", this.region, this.userPoolId);
    }

    public String getCognitoIdentityPoolUrl() {
        return String.format("https://cognito-idp.%s.amazonaws.com/%s", this.region, this.userPoolId);
    }

    public String getUserPoolId() {
        return userPoolId;
    }

    public void setUserPoolId(String userPoolId) {
        this.userPoolId = userPoolId;
    }

    public void setJwkUrl(String jwkUrl) {
        this.jwkUrl = jwkUrl;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getUserNameField() {
        return userNameField;
    }

    public void setUserNameField(String userNameField) {
        this.userNameField = userNameField;
    }

    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    public int getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
    }

	public String getHttpAuthorizationHeaderName() {
		return httpAuthorizationHeaderName;
	}

	public void setHttpAuthorizationHeaderName(String httpAuthorizationHeaderName) {
		this.httpAuthorizationHeaderName = httpAuthorizationHeaderName;
	}

    
}
