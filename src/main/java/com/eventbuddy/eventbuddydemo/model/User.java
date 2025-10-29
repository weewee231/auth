package com.eventbuddy.eventbuddydemo.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
@Setter
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String uuid = UUID.randomUUID().toString();

    @Column(unique = true, nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role;

    private String username;

    @Column(nullable = false)
    private String password;

    @Column(name = "verification_code")
    private String verificationCode;

    @Column(name = "verification_code_expires_at")
    private LocalDateTime verificationCodeExpiresAt;

    @Column(name = "refresh_token")
    private String refreshToken;

    @Column(name = "refresh_token_expires_at")
    private LocalDateTime refreshTokenExpiresAt;

    @Column(name = "reset_password_code")
    private String resetPasswordCode;

    @Column(name = "reset_password_code_expires_at")
    private LocalDateTime resetPasswordCodeExpiresAt;

    private boolean enabled = false;

    public User() {}

    public User(String email, UserRole role, String password, String username) {
        this.email = email;
        this.role = role;
        this.password = password;
        this.username = username;
        this.uuid = UUID.randomUUID().toString();
        this.enabled = false;
    }

    // Новый конструктор с тремя параметрами
    public User(String email, UserRole role, String password) {
        this.email = email;
        this.role = role;
        this.password = password;
        this.username = email.split("@")[0]; // автоматически генерируем username из email
        this.uuid = UUID.randomUUID().toString();
        this.enabled = false;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public boolean isRefreshTokenValid() {
        return refreshToken != null &&
                refreshTokenExpiresAt != null &&
                refreshTokenExpiresAt.isAfter(LocalDateTime.now());
    }

    public void invalidateRefreshToken() {
        this.refreshToken = null;
        this.refreshTokenExpiresAt = null;
    }

    public boolean isResetPasswordCodeValid() {
        return resetPasswordCode != null &&
                resetPasswordCodeExpiresAt != null &&
                resetPasswordCodeExpiresAt.isAfter(LocalDateTime.now());
    }

    public void invalidateResetPasswordCode() {
        this.resetPasswordCode = null;
        this.resetPasswordCodeExpiresAt = null;
    }

    public enum UserRole {
        INDIVIDUAL, COMPANY
    }
}