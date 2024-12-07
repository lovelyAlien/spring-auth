package com.ab108.auth.service;

import com.ab108.auth.entity.User;
import com.ab108.auth.entity.UserLog;
import com.ab108.auth.repository.UserLogRepository;
import com.ab108.auth.repository.UserRepository;
import com.ab108.auth.utils.JwtUtil;
import io.jsonwebtoken.Claims;
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

  public String login(String email, String password) {
    User user = userRepository.findUserByEmail(email);
    if(user == null) {
      userLogRepository.save(new UserLog(
        null,
        "LOGIN_FAILURE",
        LocalDateTime.now(),
        "이메일이 존재하지 않습니다."
      ));

      throw new UsernameNotFoundException("이메일이 존재하지 않습니다.");
    }

    // 암호화된 password를 디코딩한 값과 입력한 패스워드 값이 다르면 null 반환
    if(!passwordEncoder.matches(password, user.getPassword())) {
      userLogRepository.save(new UserLog(
        user,
        "LOGIN_FAILURE",
        LocalDateTime.now(),
        "비밀번호가 일치하지 않습니다."
      ));
      throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
    }

    String accessToken = jwtUtil.createAccessToken(user.getEmail(), user.getAuthority());
    userLogRepository.save(new UserLog(
      user,
      "LOGIN_SUCCESS",
      LocalDateTime.now(),
      "로그인 성공"
    ));
    return accessToken;
  }

  public void logout(String token) {
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
    userLogRepository.save(new UserLog(
      user,
      "LOGOUT",
      LocalDateTime.now(),
      "로그아웃 성공"
    ));
  }
}
