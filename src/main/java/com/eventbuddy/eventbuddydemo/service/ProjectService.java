package com.eventbuddy.eventbuddydemo.service;

import com.eventbuddy.eventbuddydemo.dto.CreateProjectDto;
import com.eventbuddy.eventbuddydemo.dto.EditProjectDto;
import com.eventbuddy.eventbuddydemo.dto.ProjectDto;
import com.eventbuddy.eventbuddydemo.exception.AuthException;
import com.eventbuddy.eventbuddydemo.model.Project;
import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.repository.ProjectRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProjectService {
    private final ProjectRepository projectRepository;

    public List<ProjectDto> getAllProjects(User owner) {
        log.info("Getting all projects for user: {}", owner.getEmail());
        return projectRepository.findByOwnerOrderByCreatedAtDesc(owner)
                .stream()
                .map(ProjectDto::new)
                .collect(Collectors.toList());
    }

    public ProjectDto getProject(UUID id, User owner) {
        log.info("Getting project {} for user: {}", id, owner.getEmail());
        Project project = projectRepository.findByIdAndOwner(id, owner)
                .orElseThrow(() -> {
                    log.warn("Project not found: {} for user: {}", id, owner.getEmail());
                    return new AuthException("Проект не найден", "id", "Проект с таким ID не найден");
                });
        return new ProjectDto(project);
    }

    @Transactional
    public ProjectDto createProject(CreateProjectDto dto, User owner) {
        log.info("Creating project '{}' for user: {}", dto.getTitle(), owner.getEmail());
        
        Project project = new Project(
                dto.getTitle(),
                dto.getDescription(),
                dto.getDeadline(),
                owner
        );
        
        Project savedProject = projectRepository.saveAndFlush(project);
        log.info("Project created with ID: {}", savedProject.getId());
        
        return new ProjectDto(savedProject);
    }

    @Transactional
    public ProjectDto updateProject(UUID id, EditProjectDto dto, User owner) {
        log.info("Updating project {} for user: {}", id, owner.getEmail());
        
        Project project = projectRepository.findByIdAndOwner(id, owner)
                .orElseThrow(() -> {
                    log.warn("Project not found for update: {} for user: {}", id, owner.getEmail());
                    return new AuthException("Проект не найден", "id", "Проект с таким ID не найден");
                });
        
        project.setTitle(dto.getTitle());
        project.setDescription(dto.getDescription());
        project.setDeadline(dto.getDeadline());
        
        Project updatedProject = projectRepository.saveAndFlush(project);
        log.info("Project updated: {}", id);
        
        return new ProjectDto(updatedProject);
    }

    @Transactional
    public void deleteProject(UUID id, User owner) {
        log.info("Deleting project {} for user: {}", id, owner.getEmail());
        
        Project project = projectRepository.findByIdAndOwner(id, owner)
                .orElseThrow(() -> {
                    log.warn("Project not found for delete: {} for user: {}", id, owner.getEmail());
                    return new AuthException("Проект не найден", "id", "Проект с таким ID не найден");
                });
        
        projectRepository.delete(project);
        log.info("Project deleted: {}", id);
    }
}

