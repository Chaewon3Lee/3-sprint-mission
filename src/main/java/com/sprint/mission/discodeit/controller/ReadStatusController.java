package com.sprint.mission.discodeit.controller;

import com.sprint.mission.discodeit.dto.request.ReadStatusCreateRequest;
import com.sprint.mission.discodeit.dto.request.ReadStatusUpdateRequest;
import com.sprint.mission.discodeit.entity.ReadStatus;
import com.sprint.mission.discodeit.service.ReadStatusService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/readStatuses")
public class ReadStatusController {

  private final ReadStatusService readStatusService;

  @PostMapping
  public ResponseEntity<ReadStatus> createReadStatus(@RequestBody ReadStatusCreateRequest request) {
    System.out.println("📥 POST /api/readStatuses");
    System.out.println(">> request body: " + request);

    ReadStatus created = readStatusService.create(request);
    return ResponseEntity.status(HttpStatus.CREATED).body(created);
  }

  @PatchMapping("/{readStatusId}")
  public ResponseEntity<ReadStatus> updateReadStatus(
      @PathVariable UUID readStatusId,
      @RequestBody ReadStatusUpdateRequest request
  ) {
    System.out.println("📥 PATCH /api/readStatuses/" + readStatusId);
    System.out.println(">> request body: " + request);

    ReadStatus updated = readStatusService.update(readStatusId, request);
    
    return ResponseEntity.ok(updated);
  }

  @GetMapping
  public ResponseEntity<List<ReadStatus>> findAllByUserId(@RequestParam UUID userId) {
    System.out.println("📥 GET /api/readStatuses?userId=" + userId);

    return ResponseEntity.ok(readStatusService.findAllByUserId(userId));
  }
}
