package com.ab108.auth.service;

import com.ab108.auth.dto.UserLogResponse;
import com.ab108.auth.entity.UserLog;
import com.ab108.auth.repository.UserLogRepository;
import com.ab108.auth.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class AdminService {

  private final UserLogRepository userLogRepository;
  private final JwtUtil jwtUtil;

  public Page<UserLogResponse> getUserLogs(Long userId, LocalDateTime startDate, LocalDateTime endDate, String logType, Pageable pageable) {
    Page<UserLog> logs = userLogRepository.findLogsByFilters(userId, startDate, endDate, logType, pageable);
    return logs.map(log -> new UserLogResponse(
      log.getId(),
      log.getLogType(),
      log.getTimestamp(),
      log.getMessage()
    ));
  }

  public void expireUserTokens(Long userId) {
    // 현재 시점을 무효화 기준 시점으로 설정
    jwtUtil.expireUserTokens(userId);
  }
}
