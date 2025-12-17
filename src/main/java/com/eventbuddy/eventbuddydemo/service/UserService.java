package com.eventbuddy.eventbuddydemo.service;

import com.eventbuddy.eventbuddydemo.dto.UserDto;
import com.eventbuddy.eventbuddydemo.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.StreamSupport;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<UserDto> allUsers() {
        return StreamSupport.stream(userRepository.findAll().spliterator(), false)
                .map(UserDto::new)
                .toList();
    }
}