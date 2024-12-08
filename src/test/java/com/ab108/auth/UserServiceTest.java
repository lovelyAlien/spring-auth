package com.ab108.auth;

import com.ab108.auth.dto.SignupRequest;
import com.ab108.auth.entity.Authority;
import com.ab108.auth.entity.User;
import com.ab108.auth.entity.UserLog;
import com.ab108.auth.exception.UnauthorizedException;
import com.ab108.auth.repository.UserLogRepository;
import com.ab108.auth.repository.UserRepository;
import com.ab108.auth.service.UserService;
import com.ab108.auth.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Date;

import static org.hamcrest.Matchers.any;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UserServiceTest {

  @Mock
  private UserRepository userRepository;

  @Mock
  private UserLogRepository userLogRepository;

  @Mock
  private JwtUtil jwtUtil;

  @Mock
  private PasswordEncoder passwordEncoder;

  @InjectMocks
  private UserService userService;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void testSignup_Success() {
    // Given
    SignupRequest request = new SignupRequest("test@example.com", "password123", "testuser");

    when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
    when(passwordEncoder.encode(request.getPassword())).thenReturn("hashedPassword");

    User savedUser = User.builder()
      .email(request.getEmail())
      .password("hashedPassword")
      .username(request.getUsername())
      .authority(Authority.ROLE_USER)
      .createdAt(LocalDateTime.now())
      .passwordUpdatedAt(LocalDateTime.now())
      .active(true)
      .build();

    when(userRepository.<User>save(Mockito.any(User.class))).thenReturn(savedUser);

    // When
    User result = userService.signup(request);

    // Then
    assertNotNull(result);
    assertEquals("test@example.com", result.getEmail());
    assertEquals("testuser", result.getUsername());
    verify(userRepository, times(1)).save(Mockito.any(User.class));
  }

  @Test
  void testSignup_EmailAlreadyExists() {
    // Given
    SignupRequest request = new SignupRequest("test@example.com", "password123", "testuser");

    when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

    // When / Then
    assertThrows(IllegalArgumentException.class, () -> userService.signup(request));
    verify(userRepository, never()).save(Mockito.any(User.class));
  }

  @Test
  void testLogin_Success() {
    // Given
    String email = "test@example.com";
    String password = "password123";

    User user = User.builder()
      .email(email)
      .password("hashedPassword")
      .username("testuser")
      .authority(Authority.ROLE_USER)
      .createdAt(LocalDateTime.now())
      .passwordUpdatedAt(LocalDateTime.now())
      .active(true)
      .build();

    when(userRepository.findUserByEmail(email)).thenReturn(user);
    when(passwordEncoder.matches(password, user.getPassword())).thenReturn(true);
    when(jwtUtil.createAccessToken(email, Authority.ROLE_USER)).thenReturn("testToken");

    // When
    String token = userService.login(email, password);

    // Then
    assertNotNull(token);
    assertEquals("testToken", token);
    verify(userLogRepository, times(1)).save(Mockito.any(UserLog.class));
  }

  @Test
  void testLogin_PasswordExpired() {
    // Given
    String email = "test@example.com";
    String password = "password123";

    User user = User.builder()
      .email(email)
      .password("hashedPassword")
      .username("testuser")
      .authority(Authority.ROLE_USER)
      .passwordUpdatedAt(LocalDateTime.now().minusDays(91))
      .createdAt(LocalDateTime.now())
      .active(true)
      .build();

    when(userRepository.findUserByEmail(email)).thenReturn(user);

    // When / Then
    UnauthorizedException exception = assertThrows(UnauthorizedException.class, () -> userService.login(email, password));
    assertEquals("비밀번호가 만료되었습니다. 비밀번호를 변경해주세요.", exception.getMessage());
    verify(jwtUtil, times(1)).expireUserTokens(user.getId());
    verify(userLogRepository, times(1)).save(Mockito.any(UserLog.class));
  }

  @Test
  void testLogin_InvalidPassword() {
    // Given
    String email = "test@example.com";
    String password = "wrongPassword";

    User user = User.builder()
      .email(email)
      .password("hashedPassword")
      .username("testuser")
      .authority(Authority.ROLE_USER)
      .createdAt(LocalDateTime.now())
      .passwordUpdatedAt(LocalDateTime.now())
      .active(true)
      .build();

    when(userRepository.findUserByEmail(email)).thenReturn(user);
    when(passwordEncoder.matches(password, user.getPassword())).thenReturn(false);

    // When / Then
    assertThrows(BadCredentialsException.class, () -> userService.login(email, password));
    verify(userLogRepository, times(1)).save(Mockito.any(UserLog.class));
  }

  @Test
  void testLogout_Success() {
    // Given
    String token = "validToken";
    String email = "test@example.com";

    User user = User.builder()
      .email(email)
      .password("hashedPassword")
      .username("testuser")
      .authority(Authority.ROLE_USER)
      .createdAt(LocalDateTime.now())
      .passwordUpdatedAt(LocalDateTime.now())
      .active(true)
      .build();

    Claims claims = mock(Claims.class);
    when(claims.getSubject()).thenReturn(email);
    when(claims.getExpiration()).thenReturn(new Date(System.currentTimeMillis() + 3600000)); // 만료 시간 설정

    when(jwtUtil.resolveToken(Mockito.any(HttpServletRequest.class))).thenReturn(token);
    when(jwtUtil.parseClaims(token)).thenReturn(claims);
    when(userRepository.findUserByEmail(email)).thenReturn(user);

    // When
    userService.logout(mock(HttpServletRequest.class));

    // Then
    verify(jwtUtil, times(1)).addToBlacklist(eq(token), anyLong());
    verify(userLogRepository, times(1)).save(Mockito.any(UserLog.class));
  }
}
