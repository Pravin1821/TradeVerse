package com.sk.tradeverse.controller;

import com.sk.tradeverse.config.JwtProvider;
import com.sk.tradeverse.model.User;
import com.sk.tradeverse.repository.UserRepository;
import com.sk.tradeverse.response.AuthResponse;
import com.sk.tradeverse.service.CustomeUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CustomeUserDetailsService customeUserDetailsService;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> register(@RequestBody User user) {

        User isEmailExists = userRepository.findByEmail(user.getEmail());
        if(isEmailExists != null){
            throw new RuntimeException("Email already exists");
        }

        User newUser =  new User();
        newUser.setFullname(user.getFullname());
        newUser.setEmail(user.getEmail());
        newUser.setPassword(user.getPassword());

        User savedUser = userRepository.save(newUser);

        Authentication authentication = new UsernamePasswordAuthenticationToken(user.getEmail(),user.getPassword());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = JwtProvider.generateToken(authentication);

        AuthResponse authResponse = new AuthResponse();
        authResponse.setJwt(jwt);
        authResponse.setStatus(true);
        authResponse.setMessage("Register success");

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> login(@RequestBody User user) {

        String email=user.getEmail();
        String password=user.getPassword();

        Authentication authentication = authenticate(email,password);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = JwtProvider.generateToken(authentication);

        AuthResponse authResponse = new AuthResponse();
        authResponse.setJwt(jwt);
        authResponse.setStatus(true);
        authResponse.setMessage("Login success");

        return ResponseEntity.ok(authResponse);
    }

    private Authentication authenticate(String email, String password) {
        UserDetails userDetails = customeUserDetailsService.loadUserByUsername(email);

        if(userDetails == null){
            throw new UsernameNotFoundException("Invalid username or password");
        }
        if (!userDetails.getPassword().replace("{noop}", "").equals(password)) {
            throw new BadCredentialsException("Invalid username or password");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
    }
}
