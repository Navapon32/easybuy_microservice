package com.example.Auth_Service.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @GetMapping("/info")
    public ResponseEntity<String> getAdminInfo() {
        return ResponseEntity.ok("Hello admin");
    }
}
