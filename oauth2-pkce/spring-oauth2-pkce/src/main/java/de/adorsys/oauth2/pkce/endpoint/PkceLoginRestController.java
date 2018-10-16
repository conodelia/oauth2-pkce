package de.adorsys.oauth2.pkce.endpoint;

import de.adorsys.oauth2.pkce.PkceProperties;
import de.adorsys.oauth2.pkce.basetypes.CodeVerifier;
import de.adorsys.oauth2.pkce.service.CookieService;
import de.adorsys.oauth2.pkce.service.LoginRedirectService;
import de.adorsys.oauth2.pkce.service.PkceTokenRequestService;
import de.adorsys.oauth2.pkce.service.UserAgentStateService;
import de.adorsys.oauth2.pkce.util.TokenConstants;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.ResponseHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
//@RequestMapping set with de.adorsys.oauth2.pkce.WebConfig
@Api(value = "OAUTH2 PKCE Login")
public class PkceLoginRestController {

    private static final Logger LOG = LoggerFactory.getLogger(PkceLoginRestController.class);

    private final PkceTokenRequestService pkceTokenRequestService;
    private final LoginRedirectService loginRedirectService;
    private final PkceProperties pkceProperties;
    private final CookieService cookieService;
    private final UserAgentStateService userAgentStateService;

    @Autowired
    public PkceLoginRestController(
            PkceTokenRequestService pkceTokenRequestService,
            LoginRedirectService loginRedirectService,
            PkceProperties pkceProperties,
            CookieService cookieService,
            UserAgentStateService userAgentStateService
    ) {
        this.pkceTokenRequestService = pkceTokenRequestService;
        this.loginRedirectService = loginRedirectService;
        this.pkceProperties = pkceProperties;
        this.cookieService = cookieService;
        this.userAgentStateService = userAgentStateService;
    }

    @ApiResponses(value = {
            @ApiResponse(
                    code = HttpServletResponse.SC_FOUND,
                    message = "Redirect to IDP login page",
                    responseHeaders = {
                            @ResponseHeader(
                                    name = "location",
                                    description = "Url to login page"
                            )
                    }
            )
    })
    @GetMapping(params = TokenConstants.REDIRECT_URI_PARAM_NAME)
    public void redirectToLoginPageWithRedirectUrl(
            HttpServletRequest request,
            @RequestParam(TokenConstants.REDIRECT_URI_PARAM_NAME) String originLocation,
            HttpServletResponse response
    ) throws IOException {
        ServletUriComponentsBuilder builder = ServletUriComponentsBuilder.fromRequestUri(request);
        String redirectUri = builder.replacePath(pkceProperties.getAuthEndpoint()).build().toUriString();

        redirectToLogin(originLocation, redirectUri, response);
    }

    @GetMapping
    public void redirectToLoginPageWithReferer(
            HttpServletRequest request,
            @RequestHeader(TokenConstants.REFERER_HEADER_KEYWORD) String referer,
            HttpServletResponse response
    ) throws IOException {
        ServletUriComponentsBuilder builder = ServletUriComponentsBuilder.fromRequestUri(request);
        String redirectUri = builder.replacePath(pkceProperties.getAuthEndpoint()).build().toUriString();

        redirectToLogin(referer, redirectUri, response);
    }

    private void redirectToLogin(String originLocation, String redirectUri, HttpServletResponse response) throws IOException {
        LoginRedirectService.LoginRedirect redirect = loginRedirectService.getRedirect(redirectUri);

        Cookie codeVerifier = createCodeVerifierCookie(redirect.getCodeVerifier());
        response.addCookie(codeVerifier);

        Cookie userAgentStateCookie = userAgentStateService.createRedirectCookie(originLocation, redirectUri);
        response.addCookie(userAgentStateCookie);

        response.sendRedirect(redirect.getRedirectUrl());
    }

    @ApiResponses(value = {
            @ApiResponse(
                    code = HttpServletResponse.SC_FOUND,
                    message = "Redirect to IDP login page",
                    responseHeaders = {
                            @ResponseHeader(
                                    name = "location",
                                    description = "Url to login page"
                            ), @ResponseHeader(
                            name = "Set-Cookie",
                            description = TokenConstants.ACCESS_TOKEN_COOKIE_NAME + "=<access-token-value>; Path=/; Secure; HttpOnly; Max-Age=<token's max-age value>"
                    ), @ResponseHeader(
                            name = "Set-Cookie",
                            description = TokenConstants.REFRESH_TOKEN_COOKIE_NAME + "=<refresh-token-value>; Path=/; Secure; HttpOnly; Max-Age=<token's max-age value>"
                    ), @ResponseHeader(
                            name = "Set-Cookie",
                            description = TokenConstants.CODE_VERIFIER_COOKIE_NAME + "=null; Path=/; Secure; HttpOnly; Max-Age=0"
                    )}
            )
    })
    @GetMapping(params = {TokenConstants.CODE_REQUEST_PARAMETER_NAME})
    public void getTokenFromCode(
            HttpServletRequest request,
            @RequestParam(TokenConstants.CODE_REQUEST_PARAMETER_NAME) String code,
            @CookieValue(name = TokenConstants.CODE_VERIFIER_COOKIE_NAME) String codeVerifier,
            @CookieValue(name = TokenConstants.USER_AGENT_STATE_COOKIE_NAME) String userAgentStateValue,
            HttpServletResponse response
    ) throws IOException {
        UserAgentStateService.UserAgentState userAgentState = userAgentStateService.readUserAgentState(userAgentStateValue);

        Cookie deleteUserAgentState = userAgentStateService.deleteUserAgentStateCookie();
        response.addCookie(deleteUserAgentState);

        getTokenForCode(code, userAgentState.getRedirectUri(), userAgentState.getUserAgentPage(), codeVerifier, response);
    }

    @ApiResponses(value = {
            @ApiResponse(
                    code = HttpServletResponse.SC_FOUND,
                    message = "Redirect to IDP login page",
                    responseHeaders = {
                            @ResponseHeader(
                                    name = "location",
                                    description = "Url to user agent"
                            ), @ResponseHeader(
                            name = "Set-Cookie",
                            description = TokenConstants.ACCESS_TOKEN_COOKIE_NAME + "=<access-token-value>; Path=/; Secure; HttpOnly; Max-Age=<token's max-age value>"
                    ), @ResponseHeader(
                            name = "Set-Cookie",
                            description = TokenConstants.REFRESH_TOKEN_COOKIE_NAME + "=<refresh-token-value>; Path=/; Secure; HttpOnly; Max-Age=<token's max-age value>"
                    ), @ResponseHeader(
                            name = "Set-Cookie",
                            description = TokenConstants.CODE_VERIFIER_COOKIE_NAME + "=null; Path=/; Secure; HttpOnly; Max-Age=0"
                    )}
            )
    })
    @GetMapping(params = {TokenConstants.CODE_REQUEST_PARAMETER_NAME, TokenConstants.REDIRECT_URI_PARAM_NAME})
    public void getToken(HttpServletRequest request,
                         @RequestParam(TokenConstants.CODE_REQUEST_PARAMETER_NAME) String code,
                         @RequestParam(name = TokenConstants.REDIRECT_URI_PARAM_NAME) String redirectUri,
                         @CookieValue(name = TokenConstants.CODE_VERIFIER_COOKIE_NAME) String codeVerifier,
                         HttpServletResponse response
    ) throws IOException {
           getTokenForCode(code, redirectUri, redirectUri, codeVerifier, response);
    }

    private void getTokenForCode(String code, String redirectUri, String originUri, String codeVerifier, HttpServletResponse response) throws IOException {
        PkceTokenRequestService.TokenResponse bearerToken = pkceTokenRequestService.requestToken(
                code,
                codeVerifier,
                redirectUri
        );

        response.addCookie(createTokenCookie(TokenConstants.ACCESS_TOKEN_COOKIE_NAME, bearerToken.getAccess_token(), bearerToken.getExpires_in()));
        response.addCookie(createTokenCookie(TokenConstants.REFRESH_TOKEN_COOKIE_NAME, bearerToken.getRefresh_token(), bearerToken.anyRefreshTokenExpireIn()));

        response.addCookie(deleteCodeVerifierCookie());

        response.sendRedirect(originUri);
    }

    // Cookie not deleted. they expire.
    private Cookie createTokenCookie(String name, String token, Long expiration) {
        return cookieService.creationCookie(name, token, "/", expiration.intValue());
    }

    private Cookie deleteCodeVerifierCookie() {
        return cookieService.deletionCookie(TokenConstants.CODE_VERIFIER_COOKIE_NAME, pkceProperties.getAuthEndpoint());
    }

    private Cookie createCodeVerifierCookie(CodeVerifier codeVerifier) {
        return cookieService.creationCookieWithDefaultDuration(TokenConstants.CODE_VERIFIER_COOKIE_NAME, codeVerifier.getValue(), pkceProperties.getAuthEndpoint());
    }
}
