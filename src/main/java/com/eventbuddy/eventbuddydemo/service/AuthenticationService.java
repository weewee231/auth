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

        if (userRepository.findByEmail(input.getEmail()).isPresent()) {
            throw new RuntimeException("Пользователь с таким email уже существует");
        }

        User user = new User(
                input.getEmail(),
                input.getRole(),
                passwordEncoder.encode(input.getPassword())
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

        return new AuthResponse(user, accessToken);
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

        return new AuthResponse(user, newAccessToken);
    }

    public AuthResponse verifyUser(VerifyUserDto input) {
        Optional<User> optionalUser = userRepository.findByEmail(input.getEmail());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (user.getVerificationCodeExpiresAt().isBefore(LocalDateTime.now())) {
                throw new RuntimeException("Срок действия кода подтверждения истек");
            }

            if (user.getVerificationCode().equals(input.getCode())) {
                user.setEnabled(true);
                user.setVerificationCode(null);
                user.setVerificationCodeExpiresAt(null);


                String autoLoginToken = jwtService.generateToken(user);
                userRepository.save(user);

                return new AuthResponse(user, autoLoginToken);
            } else {
                throw new RuntimeException("Неверный код подтверждения");
            }
        } else {
            throw new RuntimeException("Пользователь не найден");
        }
    }

    public AuthResponse autoLogin(String token) {
        try {
            String userEmail = jwtService.extractUsername(token);
            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("Пользователь не найден"));

            if (!jwtService.isTokenValid(token, user)) {
                throw new RuntimeException("Недействительный токен");
            }


            String newToken = jwtService.generateToken(user);
            return new AuthResponse(user, newToken);
        } catch (Exception e) {
            throw new RuntimeException("Ошибка автологина: " + e.getMessage());
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

    public void requestPasswordRecovery(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (!user.isEnabled()) {
                throw new RuntimeException("Аккаунт не подтвержден. Сначала подтвердите email.");
            }

            String recoveryCode = generateRecoveryCode();
            user.setResetPasswordCode(recoveryCode);
            user.setResetPasswordCodeExpiresAt(LocalDateTime.now().plusMinutes(15));

            userRepository.save(user);
            sendRecoveryEmail(user, recoveryCode);
        } else {
            throw new RuntimeException("Пользователь с таким email не найден");
        }
    }

    public void resetPassword(PasswordResetDto passwordResetDto) {
        Optional<User> optionalUser = userRepository.findByEmail(passwordResetDto.getEmail());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (!user.isResetPasswordCodeValid()) {
                throw new RuntimeException("Срок действия кода восстановления истек");
            }


            if (!user.getResetPasswordCode().equals(passwordResetDto.getCode())) {
                throw new RuntimeException("Неверный код восстановления");
            }

            user.setPassword(passwordEncoder.encode(passwordResetDto.getNewPassword()));
            user.invalidateResetPasswordCode();

            userRepository.save(user);

            sendPasswordChangedEmail(user);
        } else {
            throw new RuntimeException("Пользователь не найден");
        }
    }

    public void resendRecoveryCode(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (!user.isEnabled()) {
                throw new RuntimeException("Аккаунт не подтвержден. Сначала подтвердите email.");
            }

            String recoveryCode = generateRecoveryCode();
            user.setResetPasswordCode(recoveryCode);
            user.setResetPasswordCodeExpiresAt(LocalDateTime.now().plusMinutes(15));

            userRepository.save(user);
            sendRecoveryEmail(user, recoveryCode);
        } else {
            throw new RuntimeException("Пользователь с таким email не найден");
        }
    }

    private void sendRecoveryEmail(User user, String recoveryCode) {
        String subject = "Восстановление пароля - EventBuddy";
        String htmlMessage = "<html>"
                + "<body style=\"font-family: Arial, sans-serif;\">"
                + "<div style=\"background-color: #f5f5f5; padding: 20px;\">"
                + "<h2 style=\"color: #333;\">Восстановление пароля</h2>"
                + "<p style=\"font-size: 16px;\">Для восстановления пароля используйте следующий код:</p>"
                + "<div style=\"background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);\">"
                + "<h3 style=\"color: #333;\">Код восстановления:</h3>"
                + "<p style=\"font-size: 18px; font-weight: bold; color: #007bff;\">" + recoveryCode + "</p>"
                + "</div>"
                + "<p style=\"font-size: 14px; margin-top: 20px;\">Код действителен в течение 15 минут.</p>"
                + "<p style=\"font-size: 12px; color: #666;\">Если вы не запрашивали восстановление пароля, проигнорируйте это письмо.</p>"
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

    private void sendPasswordChangedEmail(User user) {
        String subject = "Пароль изменен - EventBuddy";
        String htmlMessage = "<html>"
                + "<body style=\"font-family: Arial, sans-serif;\">"
                + "<div style=\"background-color: #f5f5f5; padding: 20px;\">"
                + "<h2 style=\"color: #333;\">Пароль успешно изменен</h2>"
                + "<p style=\"font-size: 16px;\">Ваш пароль был успешно изменен.</p>"
                + "<div style=\"background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);\">"
                + "<p style=\"font-size: 14px;\">Если это были не вы, немедленно свяжитесь с поддержкой.</p>"
                + "</div>"
                + "<p style=\"font-size: 12px; color: #666; margin-top: 20px;\">EventBuddy Team</p>"
                + "</div>"
                + "</body>"
                + "</html>";

        try {
            emailService.sendVerificationEmail(user.getEmail(), subject, htmlMessage);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    private String generateRecoveryCode() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000;
        return String.valueOf(code);
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