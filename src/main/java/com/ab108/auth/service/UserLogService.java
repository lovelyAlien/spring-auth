package com.ab108.auth.service;

import com.ab108.auth.dto.UserLogResponse;
import com.ab108.auth.entity.UserLog;
import com.ab108.auth.repository.UserLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class UserLogService {

  private final UserLogRepository userLogRepository;

  public Page<UserLogResponse> getUserLogs(Long userId, LocalDateTime startDate, LocalDateTime endDate, String logType, Pageable pageable) {
    Page<UserLog> logs = userLogRepository.findLogsByFilters(userId, startDate, endDate, logType, pageable);
    return logs.map(log -> new UserLogResponse(
      log.getId(),
      log.getLogType(),
      log.getTimestamp(),
      log.getMessage()
    ));
  }
}
