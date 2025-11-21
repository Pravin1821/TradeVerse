package com.sk.tradeverse.controller;

import com.sk.tradeverse.config.JwtProvider;
import com.sk.tradeverse.model.TwoFactorOTP;
import com.sk.tradeverse.model.User;
import com.sk.tradeverse.repository.UserRepository;
import com.sk.tradeverse.response.AuthResponse;
import com.sk.tradeverse.service.CustomeUserDetailsService;
import com.sk.tradeverse.service.EmailService;
import com.sk.tradeverse.service.TwoFactorService;
import com.sk.tradeverse.utils.OtpUtils;
import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CustomeUserDetailsService customeUserDetailsService;

    @Autowired
    private TwoFactorService twoFactorService;

    @Autowired
    private EmailService emailService;

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
    public ResponseEntity<AuthResponse> login(@RequestBody User user) throws MessagingException {

        String email=user.getEmail();
        String password=user.getPassword();

        Authentication authentication = authenticate(email,password);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = JwtProvider.generateToken(authentication);

        User authUser = userRepository.findByEmail(email);

        if(user.getTwoFactorAuth().isEnabled()){
            AuthResponse authResponse = new AuthResponse();
            authResponse.setMessage("Two-Factor Authentication Success");
            authResponse.setTwoFactorAuthEnabled(true);
            String otp= OtpUtils.generateOtp();

            TwoFactorOTP oldTwoFactorOTP = twoFactorService.findByUser(authUser.getId());
            if(oldTwoFactorOTP != null){
                twoFactorService.deleteTwoFactorOTP(oldTwoFactorOTP);
            }

            TwoFactorOTP newTwoFactorOTP = twoFactorService.createTwoFactorOTP(authUser,otp,jwt);

            emailService.sendVerificationOtpEmail(email,otp);

            authResponse.setSession(newTwoFactorOTP.getId());

            return ResponseEntity.ok(authResponse);
        }

        AuthResponse authResponse = new AuthResponse();
        authResponse.setJwt(jwt);
        authResponse.setStatus(true);
        authResponse.setMessage("Login success");

        return ResponseEntity.ok(authResponse);
    }

    private Authentication authenticate(String email, String password) {
        UserDetails userDetails = customeUserDetailsService.loadUserByUsername(email);

        if(userDetails == null){
            throw new UsernameNotFoundException("Invalid username");
        }
        if (!userDetails.getPassword().replace("{noop}", "").equals(password)) {
            throw new BadCredentialsException("Invalid password");
        }

        return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
    }

    public ResponseEntity<AuthResponse> verifySiginOtp(@PathVariable String otp, @RequestBody String id) throws Exception {

        TwoFactorOTP twoFactorOTP=twoFactorService.findById(id);

        if(twoFactorService.verifyTwoFactorOTP(twoFactorOTP,otp))
        {
            AuthResponse authResponse = new AuthResponse();
            authResponse.setMessage("Two-Factor Authentication Verfied!");
            authResponse.setTwoFactorAuthEnabled(true);
            authResponse.setJwt(twoFactorOTP.getJwt());
            return ResponseEntity.ok(authResponse);
        }
        throw new Exception("Invalid two-factor OTP");
    }
}
