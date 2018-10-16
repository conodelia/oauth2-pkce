package de.adorsys.springoauth2;

import de.adorsys.oauth2.pkce.EnableOauth2PkceServer;
import de.adorsys.oauth2.pkce.PkceProperties;
import de.adorsys.oauth2.pkce.filter.CookiesAuthenticationFilter;
import de.adorsys.oauth2.pkce.filter.OpaqueTokenAuthenticationFilter;
import de.adorsys.oauth2.pkce.service.PkceTokenRequestService;
import de.adorsys.sts.filter.JWTAuthenticationFilter;
import de.adorsys.sts.token.authentication.TokenAuthenticationService;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableOauth2PkceServer
@Order(6)
public class MySecurityConfiguration extends WebSecurityConfigurerAdapter {

    private TokenAuthenticationService tokenAuthenticationService;
    private CookiesAuthenticationFilter cookiesAuthenticationFilter;
    private OpaqueTokenAuthenticationFilter opaqueTokenAuthenticationFilter;
    private PkceProperties pkceProperties;

    public MySecurityConfiguration(
            TokenAuthenticationService tokenAuthenticationService,
            CookiesAuthenticationFilter cookiesAuthenticationFilter,
            PkceTokenRequestService pkceTokenRequestService,
            PkceProperties pkceProperties
    ) {
        super();
        this.tokenAuthenticationService = tokenAuthenticationService;
        this.cookiesAuthenticationFilter = cookiesAuthenticationFilter;
        this.opaqueTokenAuthenticationFilter = new OpaqueTokenAuthenticationFilter(pkceTokenRequestService);
        this.pkceProperties = pkceProperties;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .authorizeRequests()
                .antMatchers(pkceProperties.getAuthEndpoint()).permitAll()
                .anyRequest().authenticated()
                .and()
            .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(pkceProperties.getAuthEndpoint()))
                .and()
            .logout()
                .logoutSuccessUrl("/").permitAll()
                .and()
            .csrf()
                .disable();

        http.addFilterBefore(new JWTAuthenticationFilter(tokenAuthenticationService), BasicAuthenticationFilter.class)
            .addFilterBefore(opaqueTokenAuthenticationFilter, JWTAuthenticationFilter.class)
            .addFilterBefore(cookiesAuthenticationFilter, OpaqueTokenAuthenticationFilter.class);
    }
}
