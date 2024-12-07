package com.ab108.auth.controller;

import com.ab108.auth.dto.UserLogResponse;
import com.ab108.auth.service.AdminService;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
public class AdminController {

  private final AdminService adminService;

  @GetMapping("/{userId}/logs")
  public Page<UserLogResponse> getUserLogs(
    @PathVariable("userId") @NotNull Long userId,
    @RequestParam(value = "startDate", required = false) String startDate,
    @RequestParam(value = "endDate", required = false) String endDate,
    @RequestParam(value = "logType", required = false) String logType,
    @RequestParam(value = "page", defaultValue = "0") int page,
    @RequestParam(value = "size", defaultValue = "10") int size) {

    LocalDateTime start = (startDate != null) ? LocalDateTime.parse(startDate) : null;
    LocalDateTime end = (endDate != null) ? LocalDateTime.parse(endDate) : null;
    Pageable pageable = PageRequest.of(page, size);

    return adminService.getUserLogs(userId, start, end, logType, pageable);
  }

  @PostMapping("/{userId}/expire-tokens")
  public ResponseEntity<?> expireUserTokens(@PathVariable Long userId) {
    try {
      adminService.expireUserTokens(userId);
      return ResponseEntity.ok("{\"message\": \"User tokens expired successfully\"}");
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body("{\"error\": \"" + e.getMessage() + "\"}");
    }
  }
}

