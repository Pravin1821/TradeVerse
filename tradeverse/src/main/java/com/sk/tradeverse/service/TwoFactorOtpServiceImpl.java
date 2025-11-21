package com.sk.tradeverse.service;

import com.sk.tradeverse.model.TwoFactorOTP;
import com.sk.tradeverse.model.User;
import com.sk.tradeverse.repository.TwoFactoryOtpRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class TwoFactorOtpServiceImpl implements TwoFactorService{

    @Autowired
    private TwoFactoryOtpRepository twoFactoryOtpRepository;

    @Override
    public TwoFactorOTP createTwoFactorOTP(User user, String otp, String jwt) {
        UUID uuid = UUID.randomUUID();

        String id = uuid.toString();

        TwoFactorOTP twoFactorOtp = new TwoFactorOTP();
        twoFactorOtp.setId(id);
        twoFactorOtp.setUser(user);
        twoFactorOtp.setOtp(otp);
        twoFactorOtp.setJwt(jwt);
        return twoFactoryOtpRepository.save(twoFactorOtp);

    }

    @Override
    public TwoFactorOTP findByUser(Long userId) {
        return twoFactoryOtpRepository.findByUserId(userId);
    }

    @Override
    public TwoFactorOTP findById(String id) {
        Optional<TwoFactorOTP> twoFactorOtp = twoFactoryOtpRepository.findById(id);
        return twoFactorOtp.orElse(null);
    }

    @Override
    public boolean verifyTwoFactorOTP(TwoFactorOTP twoFactorOTP, String otp) {
        return twoFactorOTP.getOtp().equals(otp);
    }

    @Override
    public void deleteTwoFactorOTP(TwoFactorOTP twoFactorOTP) {

        twoFactoryOtpRepository.delete(twoFactorOTP);
    }
}
