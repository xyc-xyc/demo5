package com.example.demo5.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class D1Filter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String u = request.getParameter("user");
        List<GrantedAuthority> authorities = new ArrayList<>();
        String rolesp = request.getParameter("roles");
        List<String> roles = Arrays.asList(rolesp.split("-"));
        authorities.addAll(roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_"+role.toUpperCase())).collect(Collectors.toList()));
        UserDetails user = new User(u, "", authorities);
        Authentication auth = new PreAuthenticatedAuthenticationToken(user, user.getPassword(), user.getAuthorities());
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        filterChain.doFilter(request, response);
    }
}
