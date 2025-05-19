package com.example.Auth_Service.service;

import com.example.Auth_Service.model.dto.request.LoginRequest;
import com.example.Auth_Service.model.dto.request.RegisterRequest;
import com.example.Auth_Service.model.dto.response.AuthResponse;
import com.example.Auth_Service.model.entity.User;
import com.example.Auth_Service.repository.UserRepository;
import com.example.Auth_Service.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
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
                .build();

        userRepository.save(user);

        return "User registered successfully";
    }

    public AuthResponse login (LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
            )
        );
        String token = jwtUtil.generateToken(request.getUsername());

        return new AuthResponse(token);
    }
}
