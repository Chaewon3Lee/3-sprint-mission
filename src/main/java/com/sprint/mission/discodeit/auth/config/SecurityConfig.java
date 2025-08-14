package com.sprint.mission.discodeit.auth.config;

import com.sprint.mission.discodeit.auth.handler.CustomAccessDeniedHandler;
import com.sprint.mission.discodeit.auth.handler.CustomSessionExpiredStrategy;
import com.sprint.mission.discodeit.auth.handler.LoginFailureHandler;
import com.sprint.mission.discodeit.auth.handler.LoginSuccessHandler;
import javax.sql.DataSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Slf4j
@EnableMethodSecurity
@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${remember-me.key}")
    private String rememberMeKey;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
        SessionRegistry sessionRegistry,
        LoginSuccessHandler loginSuccessHandler,
        LoginFailureHandler loginFailureHandler,
        CustomAccessDeniedHandler customAccessDeniedHandler,
        TokenBasedRememberMeServices rememberMeServices) throws Exception {
        log.debug("[SecurityConfig] Initializing SecurityFilterChain.");

        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/index.html", "/favicon.ico",
                    "/assets/**", "/css/**", "/js/**", "/images/**",
                    "/swagger-ui/**", "/v3/api-docs/**",
                    "/actuator/**", "/error")
                .permitAll()

                .requestMatchers(HttpMethod.POST, "/api/users").permitAll()
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/auth/csrf-token").permitAll()

                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                .requestMatchers("/api/**").authenticated()

                .anyRequest().permitAll()
            )
            .sessionManagement(session -> session
                .sessionFixation().migrateSession()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                .sessionRegistry(sessionRegistry)
                .expiredSessionStrategy(new CustomSessionExpiredStrategy())
            )
            .rememberMe(remember -> remember
                .rememberMeServices(rememberMeServices)
            )
            .exceptionHandling(ex -> ex
                .accessDeniedHandler(customAccessDeniedHandler)
            )
            .formLogin(login -> {
                log.debug("[SecurityConfig] Configuring form login. [loginUrl=/api/auth/login]");
                login.loginProcessingUrl("/api/auth/login")
                    .successHandler(loginSuccessHandler)
                    .failureHandler(loginFailureHandler);
            })
            .logout(logout -> {
                log.debug("[SecurityConfig] Configuring logout. [logoutUrl=/api/auth/logout]");
                logout.logoutUrl("/api/auth/logout")
                    .logoutSuccessHandler(
                        new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT));
            });

        return http.build();
    }

    @Bean
    public JdbcTokenRepositoryImpl tokenRepository(DataSource dataSource) {

        System.out.println("[SecurityConfig] JdbcTokenRepository 생성");

        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);

        System.out.println("[SecurityConfig] JdbcTokenRepository 설정 완료");
        return tokenRepository;
    }

    @Bean
    public TokenBasedRememberMeServices rememberMeServices(UserDetailsService userDetailsService) {

        TokenBasedRememberMeServices rememberMeServices = new TokenBasedRememberMeServices(
            rememberMeKey,
            userDetailsService);

        rememberMeServices.setTokenValiditySeconds(60);
        rememberMeServices.setCookieName("remember-me");
        rememberMeServices.setParameter("remember-me");

        log.debug("[SecurityConfig] Remember-Me 설정 완료");

        return rememberMeServices;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        log.debug("[SecurityConfig] Creating PasswordEncoder bean. [type=BCrypt]");
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        log.debug(
            "[SecurityConfig] Defining role hierarchy. [hierarchy=ADMIN > CHANNEL_MANAGER > USER]");
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("""
                ROLE_ADMIN > ROLE_CHANNEL_MANAGER
                ROLE_CHANNEL_MANAGER > ROLE_USER
            """);
        return hierarchy;
    }

    @Bean
    public static MethodSecurityExpressionHandler methodSecurityExpressionHandler(
        RoleHierarchy roleHierarchy) {
        log.debug("[SecurityConfig] Creating MethodSecurityExpressionHandler with RoleHierarchy.");
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public SessionRegistry sessionRegistry() {

        SessionRegistryImpl sessionRegistry = new SessionRegistryImpl() {

            @Override
            public void registerNewSession(String sessionId, Object principal) {
                System.out.println(
                    "[SessionRegistry] 새 세션 등록 - 사용자: " + principal + ", 세션ID: " + sessionId);
                super.registerNewSession(sessionId, principal);
                System.out.println(
                    "[SessionRegistry] 현재 활성 세션 수: " + getAllSessions(principal, false).size());
            }

            @Override
            public void removeSessionInformation(String sessionId) {
                System.out.println("[SessionRegistry] 세션 제거 - 세션ID: " + sessionId);
                super.removeSessionInformation(sessionId);
            }

            @Override
            public SessionInformation getSessionInformation(String sessionId) {
                SessionInformation info = super.getSessionInformation(sessionId);
                if (info != null) {
                    System.out.println("[SessionRegistry] 세션 정보 조회 - 세션ID: " + sessionId + ", 만료됨: "
                        + info.isExpired());
                }
                return info;
            }
        };

        return sessionRegistry;
    }
}
