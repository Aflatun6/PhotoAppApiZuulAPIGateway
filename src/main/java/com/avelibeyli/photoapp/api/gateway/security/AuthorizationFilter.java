package com.avelibeyli.photoapp.api.gateway.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class AuthorizationFilter extends BasicAuthenticationFilter {
    private final Environment env;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public AuthorizationFilter(AuthenticationManager authenticationManager, Environment env, SecretKey secretKey, JwtConfig jwtConfig) {
        super(authenticationManager);
        this.env = env;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String authorizationHeader = request.getHeader(env.getProperty("authorization.token.header.name"));

        if (authorizationHeader == null || !(authorizationHeader.startsWith(env.getProperty("authorization.token.header.prefix")))) {
            chain.doFilter(request, response);
            return;
        }
        UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(request);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken); // this is like authmanager.authenticate(our Authentication)
        chain.doFilter(request, response);


    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(env.getProperty("authorization.token.header.name"));
        String token = authorizationHeader.replace(env.getProperty("authorization.token.header.prefix"), "");

        try {
            String userId = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();

            if (userId == null) return null;

            return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>()); // this is the second authentication. Like first time we do it when we create user and login , next time we need to create again UsernamePasswordToken and authenticate it

        } catch (JwtException e) {
            throw new IllegalStateException(String.format("token %s cannot be trusted", token));
        }
    }
}
