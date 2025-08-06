package com.sprint.mission.discodeit.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {

    @GetMapping("/csrf-token")
    public ResponseEntity<Void> getCsrfToken(CsrfToken csrfToken) {
        log.debug("CSRF token requested: {}", csrfToken.getToken());
        return ResponseEntity.status(HttpStatus.NON_AUTHORITATIVE_INFORMATION).build();
    }
}
