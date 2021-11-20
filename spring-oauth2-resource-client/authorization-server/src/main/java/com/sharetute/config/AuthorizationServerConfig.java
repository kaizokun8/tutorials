package com.sharetute.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(@Autowired JdbcTemplate jdbcTemplate,
                                                                 @Autowired PasswordEncoder passwordEncoder) {

        JdbcRegisteredClientRepository clientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        RegisteredClientParametersMapper registeredClientParametersMapper = new RegisteredClientParametersMapper();

        registeredClientParametersMapper.setPasswordEncoder(passwordEncoder);

        clientRepository.setRegisteredClientParametersMapper(registeredClientParametersMapper);

        RegisteredClient registeredClient =
                RegisteredClient
                        .withId(UUID.randomUUID().toString())
                        .clientId("articles-client")
                        .clientSecret("secret")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .redirectUri("http://127.0.0.1:8080/login/oauth2/code/articles-client-oidc")
                        .redirectUri("http://127.0.0.1:8080/authorized")
                        .scope(OidcScopes.OPENID)
                        .scope("articles.read")
                        .clientIdIssuedAt(Instant.now())
                        //.clientSecretExpiresAt(Instant.now().plus(180, ChronoUnit.DAYS))
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(true)
                                .requireProofKey(false)
                                .build())
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofSeconds(300))
                                .refreshTokenTimeToLive(Duration.ofSeconds(3600))
                                .reuseRefreshTokens(true)
                                .idTokenSignatureAlgorithm(SignatureAlgorithm.ES256)
                                .build())
                        .build();

        clientRepository.save(registeredClient);

        return clientRepository;
    }
/*
    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(
            @Autowired JdbcTemplate jdbcTemplate,
            @Autowired RegisteredClientRepository registeredClientRepository) {

        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }
*/
    @Bean
    public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(
            @Autowired JdbcTemplate jdbcTemplate,
            @Autowired RegisteredClientRepository registeredClientRepository) {

        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer("http://localhost:12001")
                .build();
    }

    public static void main(String[] args) {

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

        String raw = "secret";

        String encoded = passwordEncoder.encode(raw);

        passwordEncoder.matches(raw, encoded);

        System.out.println(encoded);
    }

}