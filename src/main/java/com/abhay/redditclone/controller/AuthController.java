package com.abhay.redditclone.controller;

import com.abhay.redditclone.dto.AuthenticationResponse;
import com.abhay.redditclone.dto.LoginRequest;
import com.abhay.redditclone.dto.RegisterRequest;
import com.abhay.redditclone.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(
            @RequestBody RegisterRequest registerRequest) {
        authService.signup(registerRequest);
        return new ResponseEntity<>("User Registration Successful",
                HttpStatus.OK);
    }

    @GetMapping("accountVerification/{token}")
    public ResponseEntity<String> verifyAccount(@PathVariable String token) {
        authService.verifyAccount(token);
        return new ResponseEntity<>("Account Activated Successfully",
                HttpStatus.OK);
    }

    @PostMapping("/login")
    public AuthenticationResponse login (@RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest);
    }
}
