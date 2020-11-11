package com.avelibeyli.photoapp.api.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import javax.crypto.SecretKey;


@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    private final Environment env;

    @Autowired
    public WebSecurity(Environment env) {
        this.env = env;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .headers().frameOptions().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // this makes our spring security not to create session every time some client is signing in , so we need out request to be reauthorized every time they do request. OncePerRequest

        http
                .addFilter(new AuthorizationFilter(authenticationManager(), env))

                .authorizeRequests()
                .antMatchers(env.getProperty("api.h2console.url")).permitAll()
                .antMatchers(HttpMethod.POST, env.getProperty("api.signUp.url")).permitAll()
                .antMatchers(HttpMethod.POST, env.getProperty("api.login.url")).permitAll()
                .anyRequest().authenticated()
                ;
    }
}
