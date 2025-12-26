package com.eventbuddy.eventbuddydemo.service;

import com.eventbuddy.eventbuddydemo.dto.UpdateUserDto;
import com.eventbuddy.eventbuddydemo.dto.UserDto;
import com.eventbuddy.eventbuddydemo.exception.AuthException;
import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.stream.StreamSupport;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final FileStorageService fileStorageService;

    public List<UserDto> allUsers() {
        return StreamSupport.stream(userRepository.findAll().spliterator(), false)
                .map(UserDto::new)
                .toList();
    }

    @Transactional
    public UserDto updateProfile(User currentUser, UpdateUserDto dto) {
        log.info("Updating profile for user: {}", currentUser.getEmail());

        User user = userRepository.findById(currentUser.getId())
                .orElseThrow(() -> new AuthException("Пользователь не найден", "id", "Пользователь не найден"));

        if (dto.getEmail() != null && !dto.getEmail().equals(user.getEmail())) {
            if (userRepository.findByEmail(dto.getEmail()).isPresent()) {
                throw new AuthException("Ошибка обновления", "email", "Пользователь с таким email уже существует");
            }
            user.setEmail(dto.getEmail());
        }

        if (dto.getName() != null && !dto.getName().trim().isEmpty()) {
            user.setName(dto.getName());
        }

        if (dto.getPassword() != null && !dto.getPassword().trim().isEmpty()) {
            user.setPassword(passwordEncoder.encode(dto.getPassword()));
        }

        if (dto.getRole() != null) {
            user.setRole(dto.getRole());
        }

        User updatedUser = userRepository.save(user);
        log.info("Profile updated for user: {}", updatedUser.getEmail());

        return new UserDto(updatedUser);
    }

    @Transactional
    public String uploadAvatar(User currentUser, MultipartFile file) {
        log.info("Uploading avatar for user: {}", currentUser.getEmail());

        User user = userRepository.findById(currentUser.getId())
                .orElseThrow(() -> new AuthException("Пользователь не найден", "id", "Пользователь не найден"));

        String avatarUrl = fileStorageService.storeAvatar(file, user.getId());
        user.setAvatarUrl(avatarUrl);
        userRepository.save(user);

        log.info("Avatar uploaded for user: {}", currentUser.getEmail());

        return avatarUrl;
    }

    @Transactional
    public void deleteCurrentUser(User currentUser) {
        log.info("Deleting account for user: {}", currentUser.getEmail());

        User user = userRepository.findById(currentUser.getId())
                .orElseThrow(() -> new AuthException("Пользователь не найден", "id", "Пользователь не найден"));

        userRepository.delete(user);
        log.info("Account deleted for user: {}", currentUser.getEmail());
    }
}