package com.eventbuddy.eventbuddydemo.controller;

import com.eventbuddy.eventbuddydemo.dto.*;
import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.responses.AuthResponse;
import com.eventbuddy.eventbuddydemo.service.AuthenticationService;
import com.eventbuddy.eventbuddydemo.service.JwtService;
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
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        try {
            AuthResponse authResponse = authenticationService.refreshToken(refreshTokenRequest.getRefreshToken());
            return ResponseEntity.ok(authResponse);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyUser(@RequestBody VerifyUserDto verifyUserDto) {
        try {
            authenticationService.verifyUser(verifyUserDto);
            return ResponseEntity.ok("Аккаунт успешно подтвержден");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
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

                return ResponseEntity.ok("Успешный выход из системы");
            }
            return ResponseEntity.badRequest().body("Неверный токен");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Ошибка при выходе: " + e.getMessage());
        }
    }
}