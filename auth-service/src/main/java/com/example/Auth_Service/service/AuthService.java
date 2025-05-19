package com.example.Auth_Service.service;

import com.example.Auth_Service.model.dto.request.LoginRequest;
import com.example.Auth_Service.model.dto.request.RefreshTokenRequest;
import com.example.Auth_Service.model.dto.request.RegisterRequest;
import com.example.Auth_Service.model.dto.response.AuthResponse;
import com.example.Auth_Service.model.entity.RefreshToken;
import com.example.Auth_Service.model.entity.Role;
import com.example.Auth_Service.model.entity.User;
import com.example.Auth_Service.repository.RefreshTokenRepository;
import com.example.Auth_Service.repository.UserRepository;
import com.example.Auth_Service.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public String register(RegisterRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return "Username already exists";
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        userRepository.save(user);

        return "User registered successfully";
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        String accessToken = jwtUtil.generateToken(user.getUsername(), user.getRole());
        String refreshTokenStr = jwtUtil.generateRefreshToken(user.getUsername());

        RefreshToken refreshToken = RefreshToken.builder()
                .token(refreshTokenStr)
                .expiryDate(Instant.now().plusSeconds(7 * 24 * 60 * 60)) // 7 วัน
                .user(user)
                .build();
        refreshTokenRepository.save(refreshToken);

        return new AuthResponse(accessToken, refreshTokenStr);
    }

    public AuthResponse refreshToken(RefreshTokenRequest request) {
        String token = request.getRefreshToken();

        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));

        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(refreshToken);
            throw new BadCredentialsException("Refresh token expired");
        }


        User user = refreshToken.getUser();
        String username = user.getUsername();
        Role role = user.getRole();

        String newAccessToken = jwtUtil.generateToken(username, role);

        return new AuthResponse(newAccessToken, token);
    }



}
