package com.eventbuddy.eventbuddydemo.service;

import com.eventbuddy.eventbuddydemo.exception.AuthException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

@Slf4j
@Service
public class FileStorageService {

    @Value("${file.upload-dir:uploads}")
    private String uploadDir;

    @Value("${file.base-url:http://localhost:8080}")
    private String baseUrl;

    public String storeAvatar(MultipartFile file, UUID userId) {
        try {
            if (file.isEmpty()) {
                throw new AuthException("Файл пустой", "avatar", "Выберите файл для загрузки");
            }

            String contentType = file.getContentType();
            if (contentType == null || !contentType.startsWith("image/")) {
                throw new AuthException("Неверный формат файла", "avatar", "Допустимы только изображения");
            }

            long maxSize = 5 * 1024 * 1024; // 5MB
            if (file.getSize() > maxSize) {
                throw new AuthException("Файл слишком большой", "avatar", "Максимальный размер файла 5MB");
            }

            Path uploadPath = Paths.get(uploadDir, "avatars");
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            String originalFilename = file.getOriginalFilename();
            String extension = "";
            if (originalFilename != null && originalFilename.contains(".")) {
                extension = originalFilename.substring(originalFilename.lastIndexOf("."));
            }

            String filename = userId.toString() + "_" + System.currentTimeMillis() + extension;
            Path filePath = uploadPath.resolve(filename);

            Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);

            log.info("Avatar uploaded for user {}: {}", userId, filename);

            return baseUrl + "/uploads/avatars/" + filename;

        } catch (IOException e) {
            log.error("Failed to store avatar for user {}: {}", userId, e.getMessage());
            throw new AuthException("Ошибка загрузки файла", "avatar", "Не удалось сохранить файл");
        }
    }
}

