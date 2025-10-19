package com.eventbuddy.eventbuddydemo.service;

import com.eventbuddy.eventbuddydemo.dto.*;
import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.repository.UserRepository;
import com.eventbuddy.eventbuddydemo.responses.AuthResponse;
import jakarta.mail.MessagingException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final JwtService jwtService;

    public AuthenticationService(
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder,
            EmailService emailService,
            JwtService jwtService
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.jwtService = jwtService;
    }

    public User signup(RegisterUserDto input) {
        User user = new User(
                input.getEmail(),
                input.getRole(),
                passwordEncoder.encode(input.getPassword()),
                input.getUsername()
        );

        user.setVerificationCode(generateVerificationCode());
        user.setVerificationCodeExpiresAt(LocalDateTime.now().plusMinutes(15));
        user.setEnabled(false);
        sendVerificationEmail(user);
        return userRepository.save(user);
    }

    public AuthResponse authenticate(LoginUserDto input) {
        User user = userRepository.findByEmail(input.getEmail())
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));

        if (!user.isEnabled()) {
            throw new RuntimeException("Аккаунт не подтвержден. Пожалуйста, подтвердите ваш аккаунт.");
        }

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getEmail(),
                        input.getPassword()
                )
        );


        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);


        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiresAt(LocalDateTime.now().plusSeconds(jwtService.getRefreshExpirationTime() / 1000));
        userRepository.save(user);

        return new AuthResponse(accessToken, refreshToken, jwtService.getExpirationTime());
    }

    public AuthResponse refreshToken(String refreshToken) {
        if (refreshToken == null) {
            throw new RuntimeException("Refresh token отсутствует");
        }

        String userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail == null) {
            throw new RuntimeException("Неверный refresh token");
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));


        if (!jwtService.isTokenValid(refreshToken, user) ||
                !refreshToken.equals(user.getRefreshToken()) ||
                !user.isRefreshTokenValid()) {
            throw new RuntimeException("Недействительный refresh token");
        }


        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);


        user.setRefreshToken(newRefreshToken);
        user.setRefreshTokenExpiresAt(LocalDateTime.now().plusSeconds(jwtService.getRefreshExpirationTime() / 1000));
        userRepository.save(user);

        return new AuthResponse(newAccessToken, newRefreshToken, jwtService.getExpirationTime());
    }

    public void verifyUser(VerifyUserDto input) {
        Optional<User> optionalUser = userRepository.findByEmail(input.getEmail());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (user.getVerificationCodeExpiresAt().isBefore(LocalDateTime.now())) {
                throw new RuntimeException("Срок действия кода подтверждения истек");
            }

            if (user.getVerificationCode().equals(input.getVerificationCode())) {
                user.setEnabled(true);
                user.setVerificationCode(null);
                user.setVerificationCodeExpiresAt(null);
                userRepository.save(user);
            } else {
                throw new RuntimeException("Неверный код подтверждения");
            }
        } else {
            throw new RuntimeException("Пользователь не найден");
        }
    }

    public void resendVerificationCode(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (user.isEnabled()) {
                throw new RuntimeException("Аккаунт уже подтвержден");
            }
            user.setVerificationCode(generateVerificationCode());
            user.setVerificationCodeExpiresAt(LocalDateTime.now().plusHours(1));
            sendVerificationEmail(user);
            userRepository.save(user);
        } else {
            throw new RuntimeException("Пользователь не найден");
        }
    }

    public void logout(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            user.invalidateRefreshToken();
            userRepository.save(user);
        }
    }

    private void sendVerificationEmail(User user) {
        String subject = "Подтверждение аккаунта";
        String verificationCode = user.getVerificationCode();
        String htmlMessage = "<html>"
                + "<body style=\"font-family: Arial, sans-serif;\">"
                + "<div style=\"background-color: #f5f5f5; padding: 20px;\">"
                + "<h2 style=\"color: #333;\">Добро пожаловать в EventBuddy!</h2>"
                + "<p style=\"font-size: 16px;\">Пожалуйста, введите код подтверждения ниже чтобы продолжить:</p>"
                + "<div style=\"background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);\">"
                + "<h3 style=\"color: #333;\">Код подтверждения:</h3>"
                + "<p style=\"font-size: 18px; font-weight: bold; color: #007bff;\">" + verificationCode + "</p>"
                + "</div>"
                + "<p style=\"font-size: 14px; margin-top: 20px;\">Роль: " + user.getRole() + "</p>"
                + "</div>"
                + "</body>"
                + "</html>";

        try {
            emailService.sendVerificationEmail(user.getEmail(), subject, htmlMessage);
        } catch (MessagingException e) {
            e.printStackTrace();
            throw new RuntimeException("Ошибка отправки email: " + e.getMessage());
        }
    }

    private String generateVerificationCode() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000;
        return String.valueOf(code);
    }
}