package de.adorsys.oauth2.pkce.mapping;

import de.adorsys.oauth2.pkce.service.PkceTokenRequestService;
import org.adorsys.encobject.userdata.ObjectMapperSPI;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class BearerTokenMapper {

    private static final int MILLIS_PER_SECOND = 1000;

    private final ObjectMapperSPI objectMapper;

    public BearerTokenMapper(ObjectMapperSPI objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String mapToBase64(PkceTokenRequestService.TokenResponse tokenResponse) {
        Map<String, Object> values = new HashMap<>();
        values.put("access_token", tokenResponse.getAccess_token());
        values.put("token_type", tokenResponse.getToken_type());
        values.put("expires_in", tokenResponse.getExpires_in());
        values.put("refresh_token", tokenResponse.getRefresh_token());
        values.put("refresh_token_expires_in", tokenResponse.getRefresh_token_expires_in());

        String valuesAsJson;
        try {
            valuesAsJson = objectMapper.writeValueAsString(values);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return toBase64(valuesAsJson);
    }

    private static String toBase64(String value) {
        byte[] valueAsBytes = value.getBytes();
        byte[] encodedBytes = Base64.getEncoder().encode(valueAsBytes);

        return new String(encodedBytes);
    }

    public OAuth2AccessToken mapFromBase64(String tokenAsString) {
        String json = fromBase64(tokenAsString);
        return mapFromJson(json);
    }

    public OAuth2AccessToken mapFromJson(String json) {
        PkceTokenRequestService.TokenResponse tokenResponse;
        try {
            tokenResponse = objectMapper.readValue(json, PkceTokenRequestService.TokenResponse.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        BearerToken bearerToken = new BearerToken(
                tokenResponse.getAccess_token(),
                tokenResponse.getExpires_in().intValue() * MILLIS_PER_SECOND
        );

        OAuth2RefreshToken refreshToken = new RefreshToken(
                tokenResponse.getRefresh_token(),
                tokenResponse.getRefresh_token_expires_in() * MILLIS_PER_SECOND
        );

        bearerToken.setRefreshToken(refreshToken);

        return bearerToken;
    }

    private String fromBase64(String base64) {
        byte[] decodeBytes = Base64.getDecoder().decode(base64);
        return new String(decodeBytes);
    }

    private static final class BearerToken extends DefaultOAuth2AccessToken {

        private BearerToken(String value, int expireIn) {
            super(value);
            setExpiresIn(expireIn);
        }
    }

    private static final class RefreshToken extends DefaultExpiringOAuth2RefreshToken {

        private RefreshToken(String value, long expireIn) {
            super(value, new Date(System.currentTimeMillis() + expireIn));
        }
    }
}
