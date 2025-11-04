package com.eventbuddy.eventbuddydemo.controller;

import com.eventbuddy.eventbuddydemo.dto.*;
import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.responses.AuthResponse;
import com.eventbuddy.eventbuddydemo.responses.VerifyResponse;
import com.eventbuddy.eventbuddydemo.service.AuthenticationService;
import com.eventbuddy.eventbuddydemo.service.JwtService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {
    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> register(@RequestBody RegisterUserDto registerUserDto) {
        User registeredUser = authenticationService.signup(registerUserDto);
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticate(@RequestBody LoginUserDto loginUserDto) {
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

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                    .body(authResponse);
        }

        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verifyUser(@RequestBody VerifyUserDto verifyUserDto) {
        try {
            VerifyResponse verifyResponse = authenticationService.verifyUser(verifyUserDto);
            return ResponseEntity.ok(verifyResponse);
        } catch (RuntimeException e) {
            // При ошибке тоже возвращаем простой объект, но с null token
            return ResponseEntity.badRequest().body(new VerifyResponse(null));
        }
    }

    @GetMapping("/login")
    public ResponseEntity<AuthResponse> autoLogin(@RequestParam String token) {
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

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                    .body(authResponse);

        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@CookieValue(name = "refreshToken", required = false) String refreshToken) {
        try {
            if (refreshToken == null) {
                return ResponseEntity.status(401).body(null);
            }

            AuthResponse authResponse = authenticationService.refreshToken(refreshToken);

            return ResponseEntity.ok(authResponse);

        } catch (RuntimeException e) {
            return ResponseEntity.status(401).body(null);
        }
    }

    @PostMapping("/resend")
    public ResponseEntity<?> resendVerificationCode(@RequestParam String email) {
        try {
            authenticationService.resendVerificationCode(email);
            return ResponseEntity.ok("Код подтверждения отправлен");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
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

                return ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                        .body("Успешный выход из системы");
            }
            return ResponseEntity.badRequest().body("Неверный токен");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Ошибка при выходе: " + e.getMessage());
        }
    }

    @PostMapping("/recovery/request")
    public ResponseEntity<?> requestPasswordRecovery(@RequestBody RecoveryRequestDto recoveryRequestDto) {
        try {
            authenticationService.requestPasswordRecovery(recoveryRequestDto.getEmail());
            return ResponseEntity.ok("Код восстановления отправлен на email");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/recovery/reset")
    public ResponseEntity<?> resetPassword(@RequestBody PasswordResetDto passwordResetDto) {
        try {
            authenticationService.resetPassword(passwordResetDto);
            return ResponseEntity.ok("Пароль успешно изменен");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/recovery/resend")
    public ResponseEntity<?> resendRecoveryCode(@RequestBody RecoveryRequestDto recoveryRequestDto) {
        try {
            authenticationService.resendRecoveryCode(recoveryRequestDto.getEmail());
            return ResponseEntity.ok("Код восстановления отправлен повторно");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}