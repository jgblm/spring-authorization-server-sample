package top.jgblm.ch04.config;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.annotation.Nonnull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

  private final AuthenticationManager authenticationManager;
  private final JwtGenerator tokenGenerator;

  private final PasswordEncoder passwordEncoder;

  public PasswordGrantAuthenticationProvider(
      AuthenticationManager authenticationManager, JwtGenerator tokenGenerator) {
    this.authenticationManager = authenticationManager;
    this.tokenGenerator = tokenGenerator;
    this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return CustomPasswordToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    CustomPasswordToken customToken = (CustomPasswordToken) authentication;

    // Ensure the client is authenticated
    OAuth2ClientAuthenticationToken clientPrincipal =
        getAuthenticatedClientElseThrowInvalidClient(customToken);
    RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

    // Ensure the client is configured to use this authorization grant type
    if (!registeredClient.getAuthorizationGrantTypes().contains(customToken.getGrantType())) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    // Validate the client authentication
    if (!registeredClient
        .getClientAuthenticationMethods()
        .contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
    }

    if (!passwordEncoder.matches(
        (CharSequence) customToken.getCredentials(), registeredClient.getClientSecret())) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    String username = (String) customToken.getAdditionalParameters().get("username");
    String password = (String) customToken.getAdditionalParameters().get("password");

    // Validate the username and password
    UserDetails user =
        (UserDetails)
            this.authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(username, password))
                .getPrincipal();
    if (user == null) {
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    // Generate the access token
    OAuth2TokenContext tokenContext =
        DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(customToken.getGrantType())
            .authorizationGrant(customToken)
            .build();

    OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
    if (generatedAccessToken == null) {
      OAuth2Error error =
          new OAuth2Error(
              OAuth2ErrorCodes.SERVER_ERROR,
              "The token generator failed to generate the access token.",
              null);
      throw new OAuth2AuthenticationException(error);
    }
    OAuth2AccessToken accessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(),
            generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(),
            null);

    return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
  }

  /**
   * A function to retrieve the authenticated client or throw an exception if the client is invalid.
   *
   * @param authentication the authentication object
   * @return the authenticated client or an exception if the client is invalid
   */
  @Nonnull
  private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
      Authentication authentication) {
    OAuth2ClientAuthenticationToken clientPrincipal = null;
    if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(
        authentication.getPrincipal().getClass())) {
      clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
    }
    if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
      return clientPrincipal;
    }
    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
  }
}
