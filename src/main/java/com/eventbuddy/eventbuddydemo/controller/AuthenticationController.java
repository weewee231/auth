package com.eventbuddy.eventbuddydemo.controller;

import com.eventbuddy.eventbuddydemo.dto.*;
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

import java.util.Map;

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
    public ResponseEntity<UserDto> register(@RequestBody RegisterUserDto registerUserDto) {
        logger.info("POST /auth/signup - registration attempt for: {}", registerUserDto.getEmail());
        UserDto registeredUser = authenticationService.signup(registerUserDto);
        return ResponseEntity.ok(registeredUser);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticate(@RequestBody LoginUserDto loginUserDto) {
        logger.info("POST /auth/login - login attempt for: {}", loginUserDto.getEmail());
        
        AuthResponse authResponse = authenticationService.authenticate(loginUserDto);

        ResponseCookie refreshTokenCookie = ResponseCookie
                .from("refreshToken", authResponse.getRefreshToken())
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

    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verifyUser(@RequestBody VerifyUserDto verifyUserDto) {
        logger.info("POST /auth/verify - verification attempt for: {}", verifyUserDto.getEmail());
        VerifyResponse verifyResponse = authenticationService.verifyUser(verifyUserDto);
        return ResponseEntity.ok(verifyResponse);
    }

    @PostMapping("/auto-login")
    public ResponseEntity<AuthResponse> autoLogin(@RequestParam String token) {
        logger.info("POST /auth/auto-login - auto-login attempt");
        
        AuthResponse authResponse = authenticationService.processAutoLogin(token);

        ResponseCookie refreshTokenCookie = ResponseCookie
                .from("refreshToken", authResponse.getRefreshToken())
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

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@CookieValue(name = "refreshToken", required = false) String refreshToken) {
        logger.info("POST /auth/refresh - refresh token attempt");
        AuthResponse authResponse = authenticationService.refreshToken(refreshToken);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/resend")
    public ResponseEntity<Map<String, String>> resendVerificationCode(@RequestParam String email) {
        logger.info("POST /auth/resend - resend verification code for: {}", email);
        authenticationService.resendVerificationCode(email);
        return ResponseEntity.ok(Map.of("message", "Код подтверждения отправлен"));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String authHeader) {
        logger.info("POST /auth/logout - logout attempt");
        
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
                .body(Map.of("message", "Успешный выход из системы"));
    }

    @PostMapping("/recovery")
    public ResponseEntity<Map<String, String>> requestPasswordRecovery(@RequestBody RecoveryRequestDto recoveryRequestDto) {
        logger.info("POST /auth/recovery - password recovery request for: {}", recoveryRequestDto.getEmail());
        authenticationService.requestPasswordRecovery(recoveryRequestDto.getEmail());
        return ResponseEntity.ok(Map.of("message", "Код восстановления отправлен на email"));
    }

    @PostMapping("/recovery/resend")
    public ResponseEntity<Map<String, String>> resendRecoveryCode(@RequestBody RecoveryRequestDto recoveryRequestDto) {
        logger.info("POST /auth/recovery/resend - resend recovery code for: {}", recoveryRequestDto.getEmail());
        authenticationService.resendRecoveryCode(recoveryRequestDto.getEmail());
        return ResponseEntity.ok(Map.of("message", "Код восстановления отправлен повторно"));
    }
}
