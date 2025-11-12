package com.eventbuddy.eventbuddydemo.service;

import com.eventbuddy.eventbuddydemo.dto.*;
import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.repository.UserRepository;
import com.eventbuddy.eventbuddydemo.responses.AuthResponse;
import com.eventbuddy.eventbuddydemo.responses.VerifyResponse;
import jakarta.mail.MessagingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

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
        logger.info("Attempting to sign up user with email: {}", input.getEmail());

        if (userRepository.findByEmail(input.getEmail()).isPresent()) {
            logger.warn("Signup failed - user already exists with email: {}", input.getEmail());
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

        logger.info("Sending verification email to: {}", input.getEmail());
        sendVerificationEmail(user);

        User savedUser = userRepository.save(user);
        logger.info("User successfully registered with ID: {}", savedUser.getId());

        return savedUser;
    }

    public AuthResponse authenticate(LoginUserDto input) {
        logger.info("Authentication attempt for user: {}", input.getEmail());

        User user = userRepository.findByEmail(input.getEmail())
                .orElseThrow(() -> {
                    logger.warn("Authentication failed - user not found: {}", input.getEmail());
                    return new RuntimeException("Пользователь не найден");
                });

        if (!user.isEnabled()) {
            logger.warn("Authentication failed - account not enabled: {}", input.getEmail());
            throw new RuntimeException("Аккаунт не подтвержден. Пожалуйста, подтвердите ваш аккаунт.");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            input.getEmail(),
                            input.getPassword()
                    )
            );
            logger.debug("Spring Security authentication successful for: {}", input.getEmail());
        } catch (Exception e) {
            logger.error("Spring Security authentication failed for: {}", input.getEmail(), e);
            throw new RuntimeException("Неверные учетные данные");
        }

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiresAt(LocalDateTime.now().plusSeconds(jwtService.getRefreshExpirationTime() / 1000));
        userRepository.save(user);

        logger.info("Successful authentication for user: {}", input.getEmail());
        return new AuthResponse(user, accessToken);
    }

    public VerifyResponse verifyUser(VerifyUserDto input) {
        logger.info("Verification attempt for user: {}", input.getEmail());

        Optional<User> optionalUser = userRepository.findByEmail(input.getEmail());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            // Проверяем оба типа кодов: верификация email и восстановление пароля
            boolean isEmailVerification = user.getVerificationCode() != null &&
                    user.getVerificationCode().equals(input.getCode());

            boolean isPasswordRecovery = user.getResetPasswordCode() != null &&
                    user.getResetPasswordCode().equals(input.getCode());

            if (isEmailVerification) {
                logger.debug("Email verification attempt for: {}", input.getEmail());

                // Верификация email
                if (user.getVerificationCodeExpiresAt() == null ||
                        user.getVerificationCodeExpiresAt().isBefore(LocalDateTime.now())) {
                    logger.warn("Email verification failed - code expired for: {}", input.getEmail());
                    throw new RuntimeException("Срок действия кода подтверждения истек");
                }

                user.setEnabled(true);
                user.setVerificationCode(null);
                user.setVerificationCodeExpiresAt(null);

                String autoLoginCode = generateAutoLoginCode();
                user.setAutoLoginCode(autoLoginCode);
                user.setAutoLoginCodeExpiresAt(LocalDateTime.now().plusMinutes(5));
                userRepository.save(user);

                logger.info("Email successfully verified for user: {}", input.getEmail());
                return new VerifyResponse(autoLoginCode);

            } else if (isPasswordRecovery) {
                logger.debug("Password recovery verification attempt for: {}", input.getEmail());

                // Восстановление пароля - просто проверяем код
                if (user.getResetPasswordCodeExpiresAt() == null ||
                        user.getResetPasswordCodeExpiresAt().isBefore(LocalDateTime.now())) {
                    logger.warn("Password recovery verification failed - code expired for: {}", input.getEmail());
                    throw new RuntimeException("Срок действия кода восстановления истек");
                }

                String recoveryToken = generateRecoveryToken();
                user.setRecoveryToken(recoveryToken);
                user.setRecoveryTokenExpiresAt(LocalDateTime.now().plusMinutes(10));
                userRepository.save(user);

                logger.info("Password recovery code verified for user: {}", input.getEmail());
                return new VerifyResponse(recoveryToken);

            } else {
                logger.warn("Verification failed - invalid code for: {}", input.getEmail());
                throw new RuntimeException("Неверный код подтверждения");
            }
        } else {
            logger.warn("Verification failed - user not found: {}", input.getEmail());
            throw new RuntimeException("Пользователь не найден");
        }
    }

    public AuthResponse processAutoLogin(String token) {
        logger.info("Auto-login attempt with token");

        // Сначала проверяем auto-login token (email верификация)
        Optional<User> autoLoginUser = userRepository.findByAutoLoginCode(token);
        if (autoLoginUser.isPresent()) {
            User user = autoLoginUser.get();
            logger.debug("Auto-login token found for user: {}", user.getEmail());

            if (user.getAutoLoginCodeExpiresAt() == null ||
                    user.getAutoLoginCodeExpiresAt().isBefore(LocalDateTime.now())) {
                logger.warn("Auto-login failed - token expired for: {}", user.getEmail());
                throw new RuntimeException("Срок действия кода автологина истек");
            }

            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            user.setRefreshToken(refreshToken);
            user.setRefreshTokenExpiresAt(LocalDateTime.now().plusSeconds(
                    jwtService.getRefreshExpirationTime() / 1000));
            user.setAutoLoginCode(null);
            user.setAutoLoginCodeExpiresAt(null);

            userRepository.save(user);

            logger.info("Successful auto-login for user: {}", user.getEmail());
            return new AuthResponse(user, accessToken);
        }

        Optional<User> recoveryUser = userRepository.findByRecoveryToken(token);
        if (recoveryUser.isPresent()) {
            User user = recoveryUser.get();
            logger.debug("Recovery token found for user: {}", user.getEmail());

            if (user.getRecoveryTokenExpiresAt() == null ||
                    user.getRecoveryTokenExpiresAt().isBefore(LocalDateTime.now())) {
                logger.warn("Recovery auto-login failed - token expired for: {}", user.getEmail());
                throw new RuntimeException("Срок действия токена восстановления истек");
            }

            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            user.setRefreshToken(refreshToken);
            user.setRefreshTokenExpiresAt(LocalDateTime.now().plusSeconds(
                    jwtService.getRefreshExpirationTime() / 1000));

            user.setRecoveryToken(null);
            user.setRecoveryTokenExpiresAt(null);

            user.setResetPasswordCode(null);
            user.setResetPasswordCodeExpiresAt(null);

            userRepository.save(user);

            logger.info("Successful recovery auto-login for user: {}", user.getEmail());
            return new AuthResponse(user, accessToken);
        }

        logger.warn("Auto-login failed - invalid token");
        throw new RuntimeException("Недействительный токен");
    }

    public AuthResponse autoLogin(String token) {
        logger.info("JWT auto-login attempt");

        try {
            String userEmail = jwtService.extractUsername(token);
            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> {
                        logger.warn("JWT auto-login failed - user not found");
                        return new RuntimeException("Пользователь не найден");
                    });

            if (!jwtService.isTokenValid(token, user)) {
                logger.warn("JWT auto-login failed - invalid token for: {}", userEmail);
                throw new RuntimeException("Недействительный токен");
            }

            String newToken = jwtService.generateToken(user);
            logger.info("Successful JWT auto-login for user: {}", userEmail);
            return new AuthResponse(user, newToken);
        } catch (Exception e) {
            logger.error("JWT auto-login error: {}", e.getMessage(), e);
            throw new RuntimeException("Ошибка автологина: " + e.getMessage());
        }
    }

    public AuthResponse refreshToken(String refreshToken) {
        logger.info("Refresh token attempt");

        if (refreshToken == null) {
            logger.warn("Refresh token attempt failed - token is null");
            throw new RuntimeException("Refresh token отсутствует");
        }

        String userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail == null) {
            logger.warn("Refresh token attempt failed - cannot extract username");
            throw new RuntimeException("Неверный refresh token");
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> {
                    logger.warn("Refresh token attempt failed - user not found: {}", userEmail);
                    return new RuntimeException("Пользователь не найден");
                });

        if (!jwtService.isTokenValid(refreshToken, user) ||
                !refreshToken.equals(user.getRefreshToken()) ||
                !user.isRefreshTokenValid()) {
            logger.warn("Refresh token validation failed for user: {}", userEmail);
            throw new RuntimeException("Недействительный refresh token");
        }

        String newAccessToken = jwtService.generateToken(user);
        logger.info("Refresh token successful for user: {}", userEmail);

        return new AuthResponse(user, newAccessToken);
    }

    public void resendVerificationCode(String email) {
        logger.info("Resending verification code for: {}", email);

        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (user.isEnabled()) {
                logger.warn("Resend verification failed - account already enabled: {}", email);
                throw new RuntimeException("Аккаунт уже подтвержден");
            }
            user.setVerificationCode(generateVerificationCode());
            user.setVerificationCodeExpiresAt(LocalDateTime.now().plusHours(1));
            sendVerificationEmail(user);
            userRepository.save(user);
            logger.info("Verification code resent for: {}", email);
        } else {
            logger.warn("Resend verification failed - user not found: {}", email);
            throw new RuntimeException("Пользователь не найден");
        }
    }

    public void logout(String email) {
        logger.info("Logout request for user: {}", email);

        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.invalidateRefreshToken();
            userRepository.save(user);
            logger.info("Successful logout for user: {}", email);
        } else {
            logger.warn("Logout failed - user not found: {}", email);
        }
    }

    public void requestPasswordRecovery(String email) {
        logger.info("Password recovery request for: {}", email);

        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (!user.isEnabled()) {
                logger.warn("Password recovery failed - account not enabled: {}", email);
                throw new RuntimeException("Аккаунт не подтвержден. Сначала подтвердите email.");
            }

            String recoveryCode = generateRecoveryCode();
            user.setResetPasswordCode(recoveryCode);
            user.setResetPasswordCodeExpiresAt(LocalDateTime.now().plusMinutes(15));

            userRepository.save(user);
            sendRecoveryEmail(user, recoveryCode);
            logger.info("Password recovery code sent to: {}", email);
        } else {
            logger.warn("Password recovery failed - user not found: {}", email);
            throw new RuntimeException("Пользователь с таким email не найден");
        }
    }

    public void resetPassword(PasswordResetDto passwordResetDto) {
        logger.info("Password reset attempt for: {}", passwordResetDto.getEmail());

        Optional<User> optionalUser = userRepository.findByEmail(passwordResetDto.getEmail());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (!user.isResetPasswordCodeValid()) {
                logger.warn("Password reset failed - code expired for: {}", passwordResetDto.getEmail());
                throw new RuntimeException("Срок действия кода восстановления истек");
            }

            if (!user.getResetPasswordCode().equals(passwordResetDto.getCode())) {
                logger.warn("Password reset failed - invalid code for: {}", passwordResetDto.getEmail());
                throw new RuntimeException("Неверный код восстановления");
            }

            user.setPassword(passwordEncoder.encode(passwordResetDto.getNewPassword()));
            user.invalidateResetPasswordCode();

            userRepository.save(user);
            sendPasswordChangedEmail(user);
            logger.info("Password successfully reset for: {}", passwordResetDto.getEmail());
        } else {
            logger.warn("Password reset failed - user not found: {}", passwordResetDto.getEmail());
            throw new RuntimeException("Пользователь не найден");
        }
    }

    public void resendRecoveryCode(String email) {
        logger.info("Resending recovery code for: {}", email);

        Optional<User> optionalUser = userRepository.findByEmail(email);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            if (!user.isEnabled()) {
                logger.warn("Resend recovery code failed - account not enabled: {}", email);
                throw new RuntimeException("Аккаунт не подтвержден. Сначала подтвердите email.");
            }

            String recoveryCode = generateRecoveryCode();
            user.setResetPasswordCode(recoveryCode);
            user.setResetPasswordCodeExpiresAt(LocalDateTime.now().plusMinutes(15));

            userRepository.save(user);
            sendRecoveryEmail(user, recoveryCode);
            logger.info("Recovery code resent to: {}", email);
        } else {
            logger.warn("Resend recovery code failed - user not found: {}", email);
            throw new RuntimeException("Пользователь с таким email не найден");
        }
    }

    private String generateAutoLoginCode() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000;
        return String.valueOf(code);
    }

    private String generateRecoveryToken() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000;
        return String.valueOf(code);
    }

    private String generateVerificationCode() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000;
        return String.valueOf(code);
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
            logger.debug("Verification email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            logger.error("Failed to send verification email to: {}", user.getEmail(), e);
            throw new RuntimeException("Ошибка отправки email: " + e.getMessage());
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
            logger.debug("Recovery email sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            logger.error("Failed to send recovery email to: {}", user.getEmail(), e);
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
            logger.debug("Password changed notification sent to: {}", user.getEmail());
        } catch (MessagingException e) {
            logger.error("Failed to send password changed email to: {}", user.getEmail(), e);
        }
    }
}