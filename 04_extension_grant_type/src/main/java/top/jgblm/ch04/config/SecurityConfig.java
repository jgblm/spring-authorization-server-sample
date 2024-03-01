package top.jgblm.ch04.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  /** 授权服务器安全筛选器链 开发OAuth2服务，异常默认跳转/login, 使能jwt */
  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(
      HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource()));
    http
        .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .tokenEndpoint(
            tokenEndpoint ->
                tokenEndpoint
                        // 配置新的grant_type的Converter和Provider
                    .accessTokenRequestConverter(new PasswordGrantAuthenticationConverter())
                    .authenticationProvider(
                        new PasswordGrantAuthenticationProvider(
                            authenticationManager, jwtGenerator)));

    return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  /** 默认安全筛选器链 所有接口需要授权，开放form登录 */
  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
        .formLogin(Customizer.withDefaults());
    return http.build();
  }

  /**
   * user服务获取user信息
   *
   * @return {@link UserDetailsService}
   */
  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails userDetails =
        User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build();

    return new InMemoryUserDetailsManager(userDetails);
  }

  /**
   * client库获取client信息
   *
   * @return {@link RegisteredClientRepository}
   */
  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient oidcClient =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("jgblm")
            .clientSecret("{noop}123456")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(new AuthorizationGrantType("password"))
            .tokenSettings(
                TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build())
            .redirectUri("https://www.baidu.com")
            .postLogoutRedirectUri("http://127.0.0.1:8080/")
            .scope("openapi")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build();

    return new InMemoryRegisteredClientRepository(oidcClient);
  }

  /**
   * jwt解码器
   *
   * @return {@link JwtDecoder}
   */
  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey =
        new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
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
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  /**
   * 授权服务器设置endpoint
   *
   * @return {@link AuthorizationServerSettings}
   */
  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }
}
