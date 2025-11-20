package com.sk.tradeverse.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static io.jsonwebtoken.Jwts.claims;

public class JwtProvider {

    private static SecretKey secretKey = Keys.hmacShaKeyFor(JwtConstant.SECRETE_KEY.getBytes());

    public static String generateToken(Authentication authentication) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        String roles=populateAuthorities(authorities);
        String jwt= Jwts.builder()
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime()+846400000))
                .claim("email",authentication.getName())
                .claim("authorities",roles)
                .signWith(secretKey)
                .compact();
        return jwt;

    }

    public static String getEmailFromToken(String token) {
        token = token.substring(7);
        Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();

        String email=String.valueOf(claims.get("email"));
        return email;
    }
    private static String populateAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<String> auth=new HashSet<>();
        for (GrantedAuthority grantedAuthority : authorities) {
            auth.add(grantedAuthority.getAuthority());
        }
        return String.join(",", auth);
    }
}


