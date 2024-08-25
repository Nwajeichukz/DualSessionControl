package com.SessionManager.control.controller;

import com.SessionManager.control.dto.AppResponse;
import com.SessionManager.control.dto.AuthenticationRequest;
import com.SessionManager.control.dto.RegisterRequest;
import com.SessionManager.control.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;


    @PostMapping("/signup")
    public ResponseEntity<AppResponse<Map<String, Object>>> createUser(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authenticationService.createUser(request));
    }
    @PostMapping("/login")
    public ResponseEntity<AppResponse<String>> login(@RequestBody AuthenticationRequest authenticationRequest){
        return ResponseEntity.ok(authenticationService.login(authenticationRequest));
    }

    @PostMapping("/logout")
    public ResponseEntity<AppResponse<String>> logout(@RequestHeader("Authorization") String token) {
        // Remove "Bearer " prefix from token if present
        String jwtToken = token.startsWith("Bearer ") ? token.substring(7) : token;

        AppResponse<String> response = authenticationService.logout(jwtToken);
        return ResponseEntity.ok(response);
    }
}
