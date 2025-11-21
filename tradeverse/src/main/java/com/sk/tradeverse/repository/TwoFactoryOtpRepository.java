package com.sk.tradeverse.repository;


import com.sk.tradeverse.model.TwoFactorOTP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TwoFactoryOtpRepository extends JpaRepository<TwoFactorOTP,String> {
    TwoFactorOTP findByUserId(Long userId);
}
