//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.mvnsearch.config;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.session.security.web.authentication.SpringSessionRememberMeServices;
import org.springframework.util.Assert;

public class YkbSpringSessionRememberMeServices implements RememberMeServices, LogoutHandler {
    public static final String REMEMBER_ME_LOGIN_ATTR = SpringSessionRememberMeServices.class.getName() + "REMEMBER_ME_LOGIN_ATTR";
    private static final String DEFAULT_REMEMBERME_PARAMETER = "remember-me";
    private static final int THIRTY_DAYS_SECONDS = 2592000;
    private static final Log logger = LogFactory.getLog(SpringSessionRememberMeServices.class);
    private String rememberMeParameterName = "remember-me";
    private boolean alwaysRemember;
    private int validitySeconds = 2592000;
    private String sessionAttrToDeleteOnLoginFail = "SPRING_SECURITY_CONTEXT";

    public YkbSpringSessionRememberMeServices() {
    }

    public final Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
        return (RememberMeAuthenticationToken) request.getSession().getAttribute("successfulAuthentication");
    }

    public final void loginFail(HttpServletRequest request, HttpServletResponse response) {
        this.logout(request);
    }

    public final void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
        if (!this.alwaysRemember && !this.rememberMeRequested(request, this.rememberMeParameterName)) {
            logger.debug("Remember-me login not requested.");
        } else {
            request.setAttribute(REMEMBER_ME_LOGIN_ATTR, true);
            request.getSession().setMaxInactiveInterval(this.validitySeconds);
            request.getSession().setAttribute("successfulAuthentication",successfulAuthentication);
        }
    }

    protected boolean rememberMeRequested(HttpServletRequest request, String parameter) {
        String rememberMe = request.getParameter(parameter);
        if (rememberMe == null || !rememberMe.equalsIgnoreCase("true") && !rememberMe.equalsIgnoreCase("on") && !rememberMe.equalsIgnoreCase("yes") && !rememberMe.equals("1")) {
            if (logger.isDebugEnabled()) {
                logger.debug("Did not send remember-me cookie (principal did not set parameter '" + parameter + "')");
            }

            return false;
        } else {
            return true;
        }
    }

    public void setRememberMeParameterName(String rememberMeParameterName) {
        Assert.hasText(rememberMeParameterName, "rememberMeParameterName cannot be empty or null");
        this.rememberMeParameterName = rememberMeParameterName;
    }

    public void setAlwaysRemember(boolean alwaysRemember) {
        this.alwaysRemember = alwaysRemember;
    }

    public void setValiditySeconds(int validitySeconds) {
        this.validitySeconds = validitySeconds;
    }

    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        this.logout(request);
    }

    private void logout(HttpServletRequest request) {
        logger.debug("Interactive login attempt was unsuccessful.");
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(this.sessionAttrToDeleteOnLoginFail);
        }

    }
}
