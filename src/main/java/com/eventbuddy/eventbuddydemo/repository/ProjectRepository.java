package com.eventbuddy.eventbuddydemo.repository;

import com.eventbuddy.eventbuddydemo.model.Project;
import com.eventbuddy.eventbuddydemo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ProjectRepository extends JpaRepository<Project, UUID> {
    List<Project> findByOwnerOrderByCreatedAtDesc(User owner);
    Optional<Project> findByIdAndOwner(UUID id, User owner);
}

