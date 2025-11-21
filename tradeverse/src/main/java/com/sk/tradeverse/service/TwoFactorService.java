package com.sk.tradeverse.service;


import com.sk.tradeverse.model.TwoFactorOTP;
import com.sk.tradeverse.model.User;
import org.springframework.stereotype.Service;

@Service
public interface TwoFactorService {

    TwoFactorOTP createTwoFactorOTP(User user, String otp, String jwt);

    TwoFactorOTP findByUser(Long userId);

    TwoFactorOTP findById(String id);

    boolean verifyTwoFactorOTP(TwoFactorOTP twoFactorOTP, String otp);

    void deleteTwoFactorOTP(TwoFactorOTP twoFactorOTP);
}
