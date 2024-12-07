package com.ab108.auth.service;

import com.ab108.auth.dto.SignupRequest;
import com.ab108.auth.entity.Authority;
import com.ab108.auth.entity.User;
import com.ab108.auth.entity.UserLog;
import com.ab108.auth.exception.UnauthorizedException;
import com.ab108.auth.repository.UserLogRepository;
import com.ab108.auth.repository.UserRepository;
import com.ab108.auth.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class UserService {

  private final UserRepository userRepository;
  private final UserLogRepository userLogRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtUtil jwtUtil;

  /**
   * 회원가입 처리
   */
  public User signup(SignupRequest request) {
    if (userRepository.existsByEmail(request.getEmail())) {
      throw new IllegalArgumentException("Email already exists");
    }

    String hashedPassword = passwordEncoder.encode(request.getPassword());

    User user = User.builder()
      .email(request.getEmail())
      .password(hashedPassword)
      .username(request.getUsername())
      .build();

    return userRepository.save(user);
  }

  public String login(String email, String password) {
    User user = userRepository.findUserByEmail(email);
    if(user == null) {
      saveUserLog(null, "LOGIN_FAILURE", "이메일이 존재하지 않습니다.");
      throw new UsernameNotFoundException("이메일이 존재하지 않습니다.");
    }

    // 비밀번호 설정 90일 만료 조건 확인
    if (isPasswordExpired(user)) {
      saveUserLog(user, "LOGIN_FAILURE", "비밀번호가 만료되었습니다.");
      jwtUtil.expireUserTokens(user.getId()); // 기존 토큰 무효화
      throw new UnauthorizedException("비밀번호가 만료되었습니다. 비밀번호를 변경해주세요.");
    }

    // 암호화된 password를 디코딩한 값과 입력한 패스워드 값이 다르면 null 반환
    if(!passwordEncoder.matches(password, user.getPassword())) {
      saveUserLog(user, "LOGIN_FAILURE", "비밀번호가 일치하지 않습니다.");
      throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
    }

    String accessToken = jwtUtil.createAccessToken(user.getEmail(), user.getAuthority());
    saveUserLog(user, "LOGIN_SUCCESS", "로그인 성공");

    return accessToken;
  }

  public void logout(HttpServletRequest request) {
    String token = jwtUtil.resolveToken(request);
    if(token == null || jwtUtil.isBlacklisted(token)) {
      throw new IllegalArgumentException("Invalid or expired token");
    }

    Claims claims = jwtUtil.parseClaims(token);
    String email = claims.getSubject();

    // 사용자 검색
    User user = userRepository.findUserByEmail(email);
    if (user == null) {
      throw new IllegalArgumentException("Invalid token: user not found");
    }

    // 블랙리스트에 추가
    long expirationTime = claims.getExpiration().getTime();
    jwtUtil.addToBlacklist(token, expirationTime);

    // 로그아웃 기록 저장
    saveUserLog(user, "LOGOUT", "로그아웃 성공");
  }

  private void saveUserLog(User user, String logType, String message) {
    userLogRepository.save(new UserLog(
      user,
      logType,
      LocalDateTime.now(),
      message
    ));
  }

  private boolean isPasswordExpired(User user) {
    LocalDateTime passwordUpdatedAt = user.getPasswordUpdatedAt();
    return passwordUpdatedAt.isBefore(LocalDateTime.now().minusDays(90));
  }
}
