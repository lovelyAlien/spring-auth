package com.ab108.auth.utils;

import com.ab108.auth.entity.Authority;
import com.ab108.auth.entity.User;
import com.ab108.auth.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class JwtUtil {

  private final Key key;
  private final long accessTokenExpTime;
  private final UserRepository userRepository;
  // 블랙리스트 저장소
  private final Map<String, Long> blacklist = new ConcurrentHashMap<>();

  private final Map<Long, Long> invalidateTimestamps = new ConcurrentHashMap<>();

  public JwtUtil(
    @Value("${jwt.secret}") String secretKey,
    @Value("${jwt.expiration_time}") long accessTokenExpTime,
    UserRepository userRepository

  ) {
    byte[] keyBytes = Base64.getDecoder().decode(secretKey);
    this.key = Keys.hmacShaKeyFor(keyBytes);
    this.accessTokenExpTime = accessTokenExpTime;
    this.userRepository = userRepository;
  }

  /**
   * Access Token 생성
   * @param email
   * @param authority
   * @return Access Token String
   */
  public String createAccessToken(String email, Authority authority) {
    long now = System.currentTimeMillis();
    long expirationTime = now + accessTokenExpTime; // 1시간 후 만료

    return Jwts.builder()
      .setSubject(email) // sub 설정
      .claim("role", authority.name())
      .setIssuedAt(new Date(now)) // iat 설정
      .setExpiration(new Date(expirationTime)) // exp 설정
      .signWith(key, SignatureAlgorithm.HS256) // 서명
      .compact();
  }

  /**
   * 사용자가 보낸 요청 헤더의 'Authorization' 필드에서 토큰을 추출하는 메소드.
   * @param request
   * @return token(String)
   */
  public String resolveToken(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7); // "Bearer " 제거
    }
    return null; // Authorization 헤더가 없거나 잘못된 경우
  }

  /**
   * 토큰으로부터 받은 정보를 기반으로 Authentication 객체를 반환하는 메소드.
   * @param token
   * @return Authentication
   */
  public Authentication getAuthentication(String token) {
    String username = getUsername(token);
    Authority role = getRole(token);

    return new UsernamePasswordAuthenticationToken(
      username,
      null,
      AuthorityUtils.createAuthorityList(role.name())
    );
  }

  private String getUsername(String token) {
    return parseClaims(token).getSubject();
  }

  /**
   * JWT에서 권한 정보 조회
   * @param token JWT
   * @return 권한 목록
   */
  public Authority getRole(String token) {

    String role = parseClaims(token).get("role", String.class);
    return Authority.valueOf(role);
  }



  /**
   * JWT 검증
   * @param token
   * @return IsValidate
   */
  public boolean validateToken(String token) {
    try {
      String email = getUsername(token);
      User user = userRepository.findUserByEmail(email);

      if (user == null) {
        throw new IllegalArgumentException("Invalid JWT Token: User not found");
      }

      if(isBlacklisted(token)) {
        throw new IllegalArgumentException("Expired JWT Token");
      }

      // 무효화 기준 시점 이후 발급된 토큰인지 확인
      Long invalidateTimestamp = invalidateTimestamps.get(user.getId());
      if (invalidateTimestamp != null && parseClaims(token).getIssuedAt().getTime() < invalidateTimestamp) {
        throw new IllegalArgumentException("Token issued before invalidate timestamp");
      }

      // JWT 자체 유효성 확인
      Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
      return true;
    } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
      log.error("Invalid JWT Token", e);
      throw new IllegalArgumentException("Invalid JWT Token");
    } catch (ExpiredJwtException e) {
      log.warn("Expired JWT Token", e);
      throw new IllegalArgumentException("Expired JWT Token");
    } catch (UnsupportedJwtException e) {
      log.error("Unsupported JWT Token", e);
      throw new IllegalArgumentException("Unsupported JWT Token");
    } catch (IllegalArgumentException e) {
      log.error("JWT claims string is empty.", e);
      throw new IllegalArgumentException("JWT claims string is empty.");
    }
  }


  /**
   * JWT Claims 추출
   * @param token
   * @return JWT Claims
   */
  public Claims parseClaims(String token) {
    try {
      return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    } catch (ExpiredJwtException e) {
      return e.getClaims();
    }
  }


  /**
   * 블랙리스트에 토큰 추가
   * @param token 토큰
   * @param expirationTime 만료 시간 (UNIX 타임스탬프)
   */
  public void addToBlacklist(String token, long expirationTime) {
    blacklist.put(token, expirationTime);
  }

  /**
   * 토큰이 블랙리스트에 있는지 확인
   * @param token 토큰
   * @return 블랙리스트에 있으면 true, 없으면 false
   */
  public boolean isBlacklisted(String token) {
    Long expirationTime = blacklist.get(token);
    if (expirationTime == null) {
      return false;
    }

    // 만료 시간 확인
    if (System.currentTimeMillis() > expirationTime) {
      blacklist.remove(token); // 만료된 토큰은 블랙리스트에서 제거
      return false;
    }

    return true;
  }

  public void expireUserTokens(Long userId) {
    // 현재 시점을 무효화 기준 시점으로 설정
    invalidateTimestamps.put(userId, System.currentTimeMillis());
  }
}
