package com.eventbuddy.eventbuddydemo.repository;

import com.eventbuddy.eventbuddydemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmail(String email);
    Optional<User> findByVerificationCode(String verificationCode);
    Optional<User> findByAutoLoginCode(String autoLoginCode);
    Optional<User> findByRecoveryToken(String recoveryToken);
}