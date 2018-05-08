package de.adorsys.oauth2.pkce;

import de.adorsys.oauth2.pkce.context.Oauth2PkceContext;
import de.adorsys.oauth2.pkce.context.Oauth2PkceContextFactory;
import de.adorsys.oauth2.pkce.filter.TokenProcessingFilter;
import de.adorsys.oauth2.pkce.mapping.BearerTokenMapper;
import de.adorsys.oauth2.pkce.mapping.JacksonObjectMapper;
import de.adorsys.oauth2.pkce.service.AccessTokenProvider;
import de.adorsys.oauth2.pkce.service.LoginRedirectService;
import de.adorsys.oauth2.pkce.service.PkceTokenServices;
import de.adorsys.oauth2.pkce.service.PkceTokenRequestService;
import org.adorsys.encobject.userdata.ObjectMapperSPI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.*;
import org.springframework.web.client.RestTemplate;

@Configuration
@ComponentScan(basePackages = {
        "de.adorsys.oauth2.pkce"
})
public class PkceConfiguration {

    @Autowired
    PkceProperties pkceProperties;

    @Bean
    ObjectMapperSPI objectMapper() {
        return new JacksonObjectMapper();
    }

    @Bean
    BearerTokenMapper tokenJsonMapper(
            ObjectMapperSPI objectMapper
    ) {
        return new BearerTokenMapper(objectMapper);
    }

    @Bean
    TokenProcessingFilter mySsoFilter(
            BearerTokenMapper bearerTokenMapper
    ) {
        PkceTokenServices tokenServices = new PkceTokenServices(
                pkceProperties.getUserInfoUri(),
                pkceProperties.getClientId()
        );

        return new TokenProcessingFilter(tokenServices, pkceProperties, bearerTokenMapper);
    }

    @Bean
    RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder.build();
    }

    @Bean
    PkceTokenRequestService oauth2PkceTokenService(
            RestTemplate restTemplate,
            Oauth2PkceContext oauth2PkceContext
    ) {
        return new PkceTokenRequestService(restTemplate, oauth2PkceContext, pkceProperties);
    }

    @Bean
    @Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
    Oauth2PkceContext oauth2PkceContext() {
        return new Oauth2PkceContextFactory().create();
    }

    @Bean
    LoginRedirectService loginRedirectService(Oauth2PkceContext oauth2PkceContext) {
        return new LoginRedirectService(pkceProperties, oauth2PkceContext);
    }

    @Bean
    AccessTokenProvider accessTokenProvider() {
        return new AccessTokenProvider();
    }
}