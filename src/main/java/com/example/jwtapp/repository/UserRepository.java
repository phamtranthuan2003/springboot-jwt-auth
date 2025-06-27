package com.example.jwtapp.repository;

import org.springframework.stereotype.Repository;
import java.util.Optional;

import com.example.jwtapp.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);

    
}
