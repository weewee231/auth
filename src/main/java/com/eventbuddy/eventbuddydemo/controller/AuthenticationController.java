package com.eventbuddy.eventbuddydemo.controller;

import com.eventbuddy.eventbuddydemo.dto.*;
import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.responses.AuthResponse;
import com.eventbuddy.eventbuddydemo.service.AuthenticationService;
import com.eventbuddy.eventbuddydemo.service.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;

    public AuthenticationController(AuthenticationService authenticationService, JwtService jwtService) {
        this.authenticationService = authenticationService;
        this.jwtService = jwtService;
    }


    @PostMapping("/send-code")
    public ResponseEntity<?> sendCode(@RequestBody SendCodeRequest request) {
        try {
            authenticationService.sendCode(request);
            return ResponseEntity.ok().body(Map.of("message", "Код отправлен на email"));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }


    @PostMapping("/verify-code")
    public ResponseEntity<?> verifyCode(@RequestBody VerifyCodeRequest request) {
        try {
            AuthResponse response = authenticationService.verifyCode(request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }


    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        try {
            AuthResponse response = authenticationService.refreshToken(request.getRefreshToken());
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(403).body(Map.of("error", e.getMessage()));
        }
    }


    @PutMapping("/update-user")
    public ResponseEntity<?> updateUser(
            @RequestBody UpdateUserRequest request,

            @RequestHeader("Authorization") String authHeader
    ) {
        try {

            String token = authHeader.substring(7);
            String email = jwtService.extractUsername(token);


            User user = (User) authenticationService.loadUserByUsername(email);
            if (!jwtService.isTokenValid(token, user)) {
                return ResponseEntity.status(403).body(Map.of("error", "Невалидный access token"));
            }

            User updatedUser = authenticationService.updateUser(email, request);
            return ResponseEntity.ok(updatedUser);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }


    private User loadUserByUsername(String email) {

        return authenticationService.loadUserByUsername(email);
    }
}