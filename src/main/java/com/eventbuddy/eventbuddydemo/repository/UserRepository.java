package com.eventbuddy.eventbuddydemo.repository;

import com.eventbuddy.eventbuddydemo.model.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByVerificationCode(String verificationCode);
    Optional<User> findByAutoLoginCode(String autoLoginCode);
    Optional<User> findByRecoveryToken(String recoveryToken);
}