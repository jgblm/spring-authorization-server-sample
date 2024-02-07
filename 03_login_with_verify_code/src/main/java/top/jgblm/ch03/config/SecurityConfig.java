package top.jgblm.ch03.config;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.PrintWriter;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  /** 授权服务器安全筛选器链 开发OAuth2服务，异常默认跳转/login, 使能jwt */
  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    http
        // Redirect to the login page when not authenticated from the
        // authorization endpoint
        .exceptionHandling(
            (exceptions) ->
                exceptions.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
        // Accept access tokens for User Info and/or Client Registration
        .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));

    return http.build();
  }

  /** 默认安全筛选器链 所有接口需要授权，开放form登录 */
  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
            (authorize) ->
                authorize.requestMatchers("/vc.jpg").permitAll().anyRequest().authenticated())
        .formLogin(
                // 登录结果修改为json格式
            form ->
                form.successHandler(
                        (req, resp, auth) -> {
                          resp.setContentType("application/json;charset=utf-8");
                          JSONObject json = new JSONObject();
                          json.put("status", "success");
                          json.put("data", auth.getPrincipal());
                          PrintWriter out = resp.getWriter();
                          out.write(new ObjectMapper().writeValueAsString(json));
                          out.flush();
                          out.close();
                        })
                    .failureHandler(
                        (req, resp, e) -> {
                          resp.setContentType("application/json;charset=utf-8");
                          JSONObject json = new JSONObject();
                          json.put("status", "error");
                          json.put("data", e.getMessage());
                          PrintWriter out = resp.getWriter();
                          out.write(new ObjectMapper().writeValueAsString(json));
                          out.flush();
                          out.close();
                        }));

    // 自定义认证方式,校验验证码
    MyAuthenticationProvider provider = new MyAuthenticationProvider();
    provider.setUserDetailsService(userDetailsService());

    ProviderManager manager = new ProviderManager(provider);
    http.authenticationManager(manager);

    http.csrf(AbstractHttpConfigurer::disable);

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
  public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withSecretKey(
            new SecretKeySpec(CommonConstants.SIGN_KEY.getBytes(), "HMACSHA256"))
        .build();
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
