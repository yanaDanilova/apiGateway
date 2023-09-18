package com.microservices.apigateway;

import io.jsonwebtoken.*;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.WebFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

@Component
public class JwtAuthSecurityFilter extends OncePerRequestFilter  {

    @Autowired
    Environment env;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        if(isJwtValid(jwt)){ // check if this auth header exist at all, check if token is not expired and verify the Signature

            // is it enough to check if this auth header exist at all, check if token is not expired and verify the Signature ? How does it work the verification of Signature? I copy this code from you project


            //what should we do if token is valid? Create new AuthenticationToken and put it in SecurityContext? What we should use as UserDetails? Username and Password from token?


            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(new UserDetails() {
                @Override
                public Collection<? extends GrantedAuthority> getAuthorities() {
                    return null;
                }

                @Override
                public String getPassword() {
                    return null;
                }

                @Override
                public String getUsername() {
                    return null; // TO DO:  username from token
                }

                @Override
                public boolean isAccountNonExpired() {
                    return false;
                }

                @Override
                public boolean isAccountNonLocked() {
                    return false;
                }

                @Override
                public boolean isCredentialsNonExpired() {
                    return false;
                }

                @Override
                public boolean isEnabled() {
                    return false;
                }
            },null);

            authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }

        filterChain.doFilter(request, response);
    }


    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;

        String subject = null;
        Date expiration =null;

        String tokenSecret = env.getProperty("jwt.secret");
        byte[] secretKeyBytes = Base64.getEncoder().encode(tokenSecret.getBytes());
        SecretKey signingKey = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());

        JwtParser jwtParser = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build();

        Jwt<Header, Claims> parsedToken = null;
        try {

            parsedToken = jwtParser.parse(jwt);
            subject = parsedToken.getBody().getSubject();
            expiration = parsedToken.getBody().getExpiration();

        } catch (Exception ex) {
            returnValue = false;
        }

        if (subject == null || subject.isEmpty()) {
            returnValue = false;
        }

        if (expiration==null || !expiration.before(new Date())){
            returnValue= false;
        }

        return returnValue;
    }


}



