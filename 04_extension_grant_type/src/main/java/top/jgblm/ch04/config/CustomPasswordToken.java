package top.jgblm.ch04.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Collection;
import java.util.Map;

@Getter
public class CustomPasswordToken implements Authentication {

  private final Authentication clientPrincipal;

  private final Map<String, Object> additionalParameters;

  @Setter private UserDetails userDetails;

  public CustomPasswordToken(
      Authentication clientPrincipal, Map<String, Object> additionalParameters) {
    this.clientPrincipal = clientPrincipal;
    this.additionalParameters = additionalParameters;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return null;
  }

  @Override
  public Object getCredentials() {
    return clientPrincipal.getCredentials();
  }

  @Override
  public Object getDetails() {
    return clientPrincipal.getDetails();
  }

  @Override
  public Object getPrincipal() {
    return clientPrincipal;
  }

  @Override
  public boolean isAuthenticated() {
    return clientPrincipal.isAuthenticated();
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    clientPrincipal.setAuthenticated(isAuthenticated);
  }

  @Override
  public String getName() {
    return clientPrincipal.getName();
  }

  public AuthorizationGrantType getGrantType() {
    return new AuthorizationGrantType("password");
  }
}
