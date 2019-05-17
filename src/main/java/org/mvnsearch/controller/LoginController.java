package org.mvnsearch.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * login controller
 *
 * @author linux_china
 */
@Controller
public class LoginController {
    @Autowired
    private RememberMeServices rememberMeServices;
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;

    @RequestMapping(path = "/login", method = RequestMethod.GET)
    public String login(HttpServletRequest request) {
        return "login";
    }

    @RequestMapping(path = "/doLogin", method = RequestMethod.POST)
    public String doLogin(HttpServletRequest request, HttpServletResponse response) {
        String email = request.getParameter("email");
        String password = request.getParameter("password");
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);
        if (userDetails != null && passwordEncoder.matches(password, userDetails.getPassword())) {
            RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("yourAppKey", userDetails, userDetails.getAuthorities());
            Authentication authentication = this.authenticationManager.authenticate(token);
            // vvv THIS vvv
//            SecurityContextHolder
//                    .getContext()
//                    .setAuthentication(authentication);
            rememberMeServices.loginSuccess(request, response, authentication);
            return "redirect:/home";
        }
        return "login";
    }

}
