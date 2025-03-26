package com.sai.springbootoauthjwtokta.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashSet;
import java.util.Set;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
                .oauth2Login(oauth2Login ->
                        oauth2Login.userInfoEndpoint(userInfo ->
                                userInfo.userAuthoritiesMapper(grantedAuthoritiesMapper())
                        )
                );
        return http.build();
    }

    private GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcAuthority) {
                    mappedAuthorities.add(new OidcUserAuthority(
                            "OIDC_USER", oidcAuthority.getIdToken(), oidcAuthority.getUserInfo()
                    ));
                } else if (authority instanceof OAuth2UserAuthority oauth2Authority) {
                    mappedAuthorities.add(new OAuth2UserAuthority(
                            "OAUTH2_USER", oauth2Authority.getAttributes()
                    ));
                } else {
                    mappedAuthorities.add(authority);
                }
            });
            return mappedAuthorities;
        };
    }
}
