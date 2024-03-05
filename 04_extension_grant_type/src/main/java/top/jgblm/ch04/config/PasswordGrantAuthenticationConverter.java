package top.jgblm.ch04.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import top.jgblm.common.OAuth2EndpointUtils;
import top.jgblm.common.CommonConstants;

public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {
  @Override
  public Authentication convert(HttpServletRequest request) {
    String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
    if (!CommonConstants.PASSWORD_GRANT_TYPE.equals(grantType)) {
      return null;
    }
    Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

    MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

    Map<String, Object> additionalParameters = new HashMap<>();
    parameters.forEach((key, value) -> additionalParameters.put(key, value.get(0)));

    return new CustomPasswordToken(clientPrincipal, additionalParameters);
  }
}
