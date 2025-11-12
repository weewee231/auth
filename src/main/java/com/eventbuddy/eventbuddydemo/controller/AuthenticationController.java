package com.eventbuddy.eventbuddydemo.controller;

import com.eventbuddy.eventbuddydemo.dto.*;
import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.responses.AuthResponse;
import com.eventbuddy.eventbuddydemo.responses.VerifyResponse;
import com.eventbuddy.eventbuddydemo.service.AuthenticationService;
import com.eventbuddy.eventbuddydemo.service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> register(@RequestBody RegisterUserDto registerUserDto) {
        logger.info("POST /auth/signup - registration attempt for: {}", registerUserDto.getEmail());

        try {
            User registeredUser = authenticationService.signup(registerUserDto);
            logger.info("Registration successful for: {}", registerUserDto.getEmail());
            return ResponseEntity.ok(registeredUser);
        } catch (Exception e) {
            logger.error("Registration failed for: {}", registerUserDto.getEmail(), e);
            throw e;
        }
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticate(@RequestBody LoginUserDto loginUserDto) {
        logger.info("POST /auth/login - login attempt for: {}", loginUserDto.getEmail());

        try {
            AuthResponse authResponse = authenticationService.authenticate(loginUserDto);

            if (authResponse.getUser().getRefreshToken() != null) {
                ResponseCookie refreshTokenCookie = ResponseCookie
                        .from("refreshToken", authResponse.getUser().getRefreshToken())
                        .httpOnly(true)
                        .secure(true)
                        .sameSite("None")
                        .maxAge(30 * 24 * 60 * 60)
                        .path("/")
                        .build();

                logger.info("Login successful with refresh token for: {}", loginUserDto.getEmail());
                return ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                        .body(authResponse);
            }

            logger.info("Login successful for: {}", loginUserDto.getEmail());
            return ResponseEntity.ok(authResponse);
        } catch (Exception e) {
            logger.error("Login failed for: {}", loginUserDto.getEmail(), e);
            throw e;
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verifyUser(@RequestBody VerifyUserDto verifyUserDto) {
        logger.info("POST /auth/verify - verification attempt for: {}", verifyUserDto.getEmail());

        try {
            VerifyResponse verifyResponse = authenticationService.verifyUser(verifyUserDto);
            logger.info("Verification successful for: {}", verifyUserDto.getEmail());
            return ResponseEntity.ok(verifyResponse);
        } catch (RuntimeException e) {
            logger.error("Verification failed for: {}", verifyUserDto.getEmail(), e);
            return ResponseEntity.badRequest().body(new VerifyResponse(null));
        }
    }

    @PostMapping("/auto-login")
    public ResponseEntity<AuthResponse> autoLogin(@RequestParam String token) {
        logger.info("POST /auth/auto-login - auto-login attempt");

        try {
            AuthResponse authResponse = authenticationService.processAutoLogin(token);

            User user = authResponse.getUser();
            ResponseCookie refreshTokenCookie = ResponseCookie
                    .from("refreshToken", user.getRefreshToken())
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("None")
                    .maxAge(30 * 24 * 60 * 60)
                    .path("/")
                    .build();

            logger.info("Auto-login successful for: {}", user.getEmail());
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                    .body(authResponse);

        } catch (RuntimeException e) {
            logger.error("Auto-login failed", e);
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@CookieValue(name = "refreshToken", required = false) String refreshToken) {
        logger.info("POST /auth/refresh - refresh token attempt");

        try {
            if (refreshToken == null) {
                logger.warn("Refresh token attempt failed - no token in cookies");
                return ResponseEntity.status(401).body(null);
            }

            AuthResponse authResponse = authenticationService.refreshToken(refreshToken);
            logger.info("Refresh token successful");
            return ResponseEntity.ok(authResponse);

        } catch (RuntimeException e) {
            logger.error("Refresh token failed", e);
            return ResponseEntity.status(401).body(null);
        }
    }

    @PostMapping("/resend")
    public ResponseEntity<?> resendVerificationCode(@RequestParam String email) {
        logger.info("POST /auth/resend - resend verification code for: {}", email);

        try {
            authenticationService.resendVerificationCode(email);
            logger.info("Verification code resent to: {}", email);
            return ResponseEntity.ok("Код подтверждения отправлен");
        } catch (RuntimeException e) {
            logger.error("Resend verification code failed for: {}", email, e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        logger.info("POST /auth/logout - logout attempt");

        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String jwt = authHeader.substring(7);
                String userEmail = jwtService.extractUsername(jwt);

                authenticationService.logout(userEmail);

                ResponseCookie refreshTokenCookie = ResponseCookie
                        .from("refreshToken", "")
                        .httpOnly(true)
                        .secure(true)
                        .sameSite("None")
                        .maxAge(0)
                        .path("/")
                        .build();

                logger.info("Logout successful for: {}", userEmail);
                return ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                        .body("Успешный выход из системы");
            }
            logger.warn("Logout failed - invalid authorization header");
            return ResponseEntity.badRequest().body("Неверный токен");
        } catch (Exception e) {
            logger.error("Logout failed", e);
            return ResponseEntity.badRequest().body("Ошибка при выходе: " + e.getMessage());
        }
    }

    @PostMapping("/recovery")
    public ResponseEntity<?> requestPasswordRecovery(@RequestBody RecoveryRequestDto recoveryRequestDto) {
        logger.info("POST /auth/recovery - password recovery request for: {}", recoveryRequestDto.getEmail());

        try {
            authenticationService.requestPasswordRecovery(recoveryRequestDto.getEmail());
            logger.info("Password recovery code sent to: {}", recoveryRequestDto.getEmail());
            return ResponseEntity.ok("Код восстановления отправлен на email");
        } catch (RuntimeException e) {
            logger.error("Password recovery request failed for: {}", recoveryRequestDto.getEmail(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/recovery/resend")
    public ResponseEntity<?> resendRecoveryCode(@RequestBody RecoveryRequestDto recoveryRequestDto) {
        logger.info("POST /auth/recovery/resend - resend recovery code for: {}", recoveryRequestDto.getEmail());

        try {
            authenticationService.resendRecoveryCode(recoveryRequestDto.getEmail());
            logger.info("Recovery code resent to: {}", recoveryRequestDto.getEmail());
            return ResponseEntity.ok("Код восстановления отправлен повторно");
        } catch (RuntimeException e) {
            logger.error("Resend recovery code failed for: {}", recoveryRequestDto.getEmail(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}