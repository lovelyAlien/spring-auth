package com.ab108.auth.service;

import com.ab108.auth.entity.User;
import com.ab108.auth.repository.UserRepository;
import com.ab108.auth.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class UserService {

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtUtil jwtUtil;

  public String login(String email, String password) {
    User user = userRepository.findUserByEmail(email);
    if(user == null) {
      throw new UsernameNotFoundException("이메일이 존재하지 않습니다.");
    }

    // 암호화된 password를 디코딩한 값과 입력한 패스워드 값이 다르면 null 반환
    if(!passwordEncoder.matches(password, user.getPassword())) {
      throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
    }

    String accessToken = jwtUtil.createAccessToken(user.getEmail());
    return accessToken;
  }

  public void logout(String token) {
    if(token == null || jwtUtil.isBlacklisted(token)) {
      throw new IllegalArgumentException("Invalid or expired token");
    }

    Claims claims = jwtUtil.parseClaims(token);

    // 토큰 만료 시간 계산
    long expirationTime = claims.getExpiration().getTime();

    // 블랙리스트에 추가
    jwtUtil.addToBlacklist(token, expirationTime);
  }
}
