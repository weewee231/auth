package com.eventbuddy.eventbuddydemo.service;

import com.eventbuddy.eventbuddydemo.dto.SendCodeRequest;
import com.eventbuddy.eventbuddydemo.dto.VerifyCodeRequest;
import com.eventbuddy.eventbuddydemo.dto.UpdateUserRequest;
import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.repository.UserRepository;
import com.eventbuddy.eventbuddydemo.responses.AuthResponse;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final EmailService emailService;

    public AuthenticationService(
            UserRepository userRepository,
            JwtService jwtService,
            EmailService emailService
    ) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.emailService = emailService;
    }

    public void sendCode(SendCodeRequest request) {
        String email = request.getEmail();
        Optional<User> existingUser = userRepository.findByEmail(email);

        String verificationCode = generate6DigitCode();
        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(5);

        if (existingUser.isPresent()) {

            User user = existingUser.get();
            user.setVerificationCode(verificationCode);
            user.setVerificationCodeExpiresAt(expiresAt);
            userRepository.save(user);
        } else {

            User newUser = new User();
            newUser.setEmail(email);
            newUser.setRole(User.UserRole.INDIVIDUAL);
            newUser.setVerificationCode(verificationCode);
            newUser.setVerificationCodeExpiresAt(expiresAt);
            userRepository.save(newUser);
        }

        sendVerificationEmail(email, verificationCode);
    }

    public AuthResponse verifyCode(VerifyCodeRequest request) {
        Optional<User> optionalUser = userRepository.findByEmail(request.getEmail());

        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Пользователь не найден");
        }

        User user = optionalUser.get();

        validateVerificationCode(user);

        if (!user.getVerificationCode().equals(request.getCode())) {
            throw new RuntimeException("Неверный код верификации");
        }

        User.UserRole role = validateAndGetRole(request.getRole());
        user.setRole(role);

        user.setEnabled(true);
        user.setVerificationCode(null);
        user.setVerificationCodeExpiresAt(null);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiresAt(LocalDateTime.now().plusDays(30));

        User savedUser = userRepository.save(user);

        return new AuthResponse(accessToken, refreshToken, savedUser);
    }


    public AuthResponse refreshToken(String refreshToken) {

        if (!jwtService.isRefreshTokenValid(refreshToken)) {
            throw new RuntimeException("Невалидный refresh token");
        }

        String email = jwtService.extractUsername(refreshToken);
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Пользователь не найден");
        }

        User user = optionalUser.get();

        validateRefreshToken(user, refreshToken);

        String newAccessToken = jwtService.generateAccessToken(user);

        return new AuthResponse(newAccessToken, refreshToken, user);
    }


    public User updateUser(String email, UpdateUserRequest request) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            throw new RuntimeException("Пользователь не найден");
        }

        User user = optionalUser.get();

        if (request.getUsername() != null && !request.getUsername().trim().isEmpty()) {
            user.setUsername(request.getUsername());
        }

        return userRepository.save(user);
    }



    private void validateVerificationCode(User user) {
        if (user.getVerificationCode() == null ||
                user.getVerificationCodeExpiresAt() == null) {
            throw new RuntimeException("Код верификации не существует");
        }

        if (user.getVerificationCodeExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Срок действия кода истек");
        }
    }

    private User.UserRole validateAndGetRole(String roleString) {
        try {
            return User.UserRole.valueOf(roleString.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Неверная роль. Допустимые значения: INDIVIDUAL, COMPANY");
        }
    }

    private void validateRefreshToken(User user, String refreshToken) {
        if (!refreshToken.equals(user.getRefreshToken())) {
            throw new RuntimeException("Refresh token не совпадает");
        }

        if (user.getRefreshTokenExpiresAt() == null ||
                user.getRefreshTokenExpiresAt().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Refresh token истек");
        }
    }

    private String generate6DigitCode() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000;
        return String.valueOf(code);
    }

    private void sendVerificationEmail(String email, String code) {
        String subject = "Код подтверждения для EventBuddy";
        String htmlMessage = "<html>" +
                "<body style=\"font-family: Arial, sans-serif;\">" +
                "<div style=\"background-color: #f5f5f5; padding: 20px;\">" +
                "<h2 style=\"color: #333;\">Ваш код подтверждения</h2>" +
                "<p style=\"font-size: 16px;\">Используйте этот код для входа в EventBuddy:</p>" +
                "<div style=\"background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);\">" +
                "<h3 style=\"color: #333;\">Код подтверждения:</h3>" +
                "<p style=\"font-size: 24px; font-weight: bold; color: #007bff;\">" + code + "</p>" +
                "</div>" +
                "<p style=\"font-size: 14px; color: #666; margin-top: 20px;\">Код действителен в течение 5 минут</p>" +
                "</div>" +
                "</body>" +
                "</html>";

        try {
            emailService.sendVerificationEmail(email, subject, htmlMessage);
        } catch (Exception e) {
            throw new RuntimeException("Ошибка отправки email: " + e.getMessage());
        }
    }

    public User loadUserByUsername(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));
    }
}