package com.example.Auth_Service.repository;

import com.example.Auth_Service.model.entity.RefreshToken;
import com.example.Auth_Service.model.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUser(User user);
}