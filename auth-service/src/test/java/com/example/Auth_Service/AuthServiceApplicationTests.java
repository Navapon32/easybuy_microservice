package com.example.Auth_Service;

import com.example.Auth_Service.model.dto.request.LoginRequest;
import com.example.Auth_Service.model.dto.request.RefreshTokenRequest;
import com.example.Auth_Service.model.dto.request.RegisterRequest;
import com.example.Auth_Service.model.dto.response.AuthResponse;
import com.example.Auth_Service.model.entity.RefreshToken;
import com.example.Auth_Service.model.entity.Role;
import com.example.Auth_Service.model.entity.User;
import com.example.Auth_Service.repository.RefreshTokenRepository;
import com.example.Auth_Service.repository.UserRepository;
import com.example.Auth_Service.service.AuthService;
import com.example.Auth_Service.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceApplicationTests {

	@InjectMocks
	private AuthService authService;

	@Mock private UserRepository userRepository;
	@Mock private RefreshTokenRepository refreshTokenRepository;
	@Mock private PasswordEncoder passwordEncoder;
	@Mock private AuthenticationManager authenticationManager;
	@Mock private JwtUtil jwtUtil;



	@Test
	void shouldBeSuccessWhenRegister() {
		RegisterRequest req = new RegisterRequest();
		req.setUsername("test");
		req.setPassword("pass");
		req.setRole(Role.USER);

		when(userRepository.findByUsername("test")).thenReturn(Optional.empty());
		when(passwordEncoder.encode("pass")).thenReturn("encoded");

		String result = authService.register(req);


		assertEquals("User registered successfully", result);
		verify(userRepository).save(any(User.class));
	}

	@Test
	void shouldBeFailWhenUserIsAlreadyExists() {
		RegisterRequest req = new RegisterRequest();
		req.setUsername("test");
		req.setPassword("pass");
		req.setRole(Role.USER);

		when(userRepository.findByUsername("test"))
				.thenReturn(Optional.of(User.builder().username("test").build()));

		String result = authService.register(req);


		assertEquals("Username already exists", result);

		verify(userRepository, never()).save(any(User.class));
	}


	@Test
	void shouldBeSuccessWhenLogin() {
		LoginRequest request = new LoginRequest();
		request.setUsername("user");
		request.setPassword("password");

		Role roleUser = Role.USER;

		User user = User.builder()
				.username("user")
				.password("password")
				.role(roleUser)
				.build();
		when(userRepository.findByUsername(request.getUsername())).thenReturn(Optional.ofNullable(user));
		when(jwtUtil.generateToken(request.getUsername(), user.getRole())).thenReturn("accessToken");
		when(jwtUtil.generateRefreshToken(request.getUsername())).thenReturn("refreshToken");

		AuthResponse result = authService.login(request);

		assertEquals("accessToken", result.getAccessToken());
		assertEquals("refreshToken", result.getRefreshToken());

	}

	@Test
	void shouldBeSuccessWhenCreateRefreshTokenSuccess() {
		RefreshTokenRequest req = new RefreshTokenRequest();
		req.setRefreshToken("valid-token");

		User user = User.builder().username("user").role(Role.USER).build();
		RefreshToken refreshToken = RefreshToken.builder()
				.token("valid-token")
				.expiryDate(Instant.now().plusSeconds(3600))
				.user(user)
				.build();

		when(refreshTokenRepository.findByToken("valid-token")).thenReturn(Optional.of(refreshToken));
		when(jwtUtil.generateToken("user", Role.USER)).thenReturn("new-access-token");

		AuthResponse response = authService.refreshToken(req);
		assertEquals("new-access-token", response.getAccessToken());
		assertEquals("valid-token", response.getRefreshToken());
	}
}
