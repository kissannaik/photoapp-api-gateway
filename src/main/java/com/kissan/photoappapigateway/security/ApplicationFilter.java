package com.kissan.photoappapigateway.security;

import io.jsonwebtoken.Jwts;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class ApplicationFilter extends BasicAuthenticationFilter {
    private Environment environment;


    public ApplicationFilter(AuthenticationManager authenticationManager, Environment environment) {
        super(authenticationManager);
        this.environment = environment;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        String authorizationHeader = request.getHeader(environment.getProperty("authorization.token.header.name"));

        if(authorizationHeader == null || !authorizationHeader.startsWith(environment.getProperty("authorization.token.header.prefix"))){
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(authorizationHeader);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String authorizationHeader){
        String token = authorizationHeader.replace(environment.getProperty("authorization.token.header.prefix"), "");
        System.out.println("environment.getProperty(\"token.secret\") in API Gateway = " + environment.getProperty("token.secret"));
        String userId = Jwts.parser()
                .setSigningKey(environment.getProperty("token.secret"))
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        System.out.println("userId in API Gateway = " + userId);
        if(userId == null)
            return null;

        return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
    }

}
