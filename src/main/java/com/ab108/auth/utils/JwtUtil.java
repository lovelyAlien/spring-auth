package com.ab108.auth.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtUtil {

  private final Key key;
  private final long accessTokenExpTime;

  public JwtUtil(
    @Value("${jwt.secret}") String secretKey,
    @Value("${jwt.expiration_time}") long accessTokenExpTime
  ) {
    byte[] keyBytes = Base64.getDecoder().decode(secretKey);
    this.key = Keys.hmacShaKeyFor(keyBytes);
    this.accessTokenExpTime = accessTokenExpTime;
  }

  /**
   * Access Token 생성
   * @param email
   * @return Access Token String
   */
  public String createAccessToken(String email) {
    return createToken(email, accessTokenExpTime);
  }


  /**
   * JWT 생성
   * @param email
   * @param expireTime
   * @return JWT String
   */
  private String createToken(String email, long expireTime) {
    long now = System.currentTimeMillis();
    long expirationTime = now + expireTime; // 1시간 후 만료

    return Jwts.builder()
      .setSubject(email) // sub 설정
      .setIssuedAt(new Date(now)) // iat 설정
      .setExpiration(new Date(expirationTime)) // exp 설정
      .signWith(key, SignatureAlgorithm.HS256) // 서명
      .compact();
  }


  /**
   * Token에서 User ID 추출
   * @param token
   * @return User ID
   */
  public Long getUserId(String token) {
    return parseClaims(token).get("memberId", Long.class);
  }


  /**
   * JWT 검증
   * @param token
   * @return IsValidate
   */
  public boolean validateToken(String token) {
    try {
      Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
      return true;
    } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
      log.info("Invalid JWT Token", e);
    } catch (ExpiredJwtException e) {
      log.info("Expired JWT Token", e);
    } catch (UnsupportedJwtException e) {
      log.info("Unsupported JWT Token", e);
    } catch (IllegalArgumentException e) {
      log.info("JWT claims string is empty.", e);
    }
    return false;
  }


  /**
   * JWT Claims 추출
   * @param accessToken
   * @return JWT Claims
   */
  public Claims parseClaims(String accessToken) {
    try {
      return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
    } catch (ExpiredJwtException e) {
      return e.getClaims();
    }
  }


}
