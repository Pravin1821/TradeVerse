package com.sk.tradeverse.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private JavaMailSender mailSender;

    public void sendVerificationOtpEmail(String email, String otp) throws MessagingException {
        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

        String subject = "Verify OTP";
        String text = "Your verification code is: " + otp;

        helper.setSubject(subject);
        helper.setText(text);
        helper.setTo(email);
        try{
            mailSender.send(mimeMessage);
        }
        catch(Exception e){
            throw new MessagingException(e.getMessage());
        }
    }
}
