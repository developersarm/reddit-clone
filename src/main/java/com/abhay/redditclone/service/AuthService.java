package com.abhay.redditclone.service;

import com.abhay.redditclone.dto.AuthenticationResponse;
import com.abhay.redditclone.dto.LoginRequest;
import com.abhay.redditclone.dto.RegisterRequest;
import com.abhay.redditclone.exception.SpringRedditException;
import com.abhay.redditclone.model.NotificationEmail;
import com.abhay.redditclone.model.User;
import com.abhay.redditclone.model.VerificationToken;
import com.abhay.redditclone.repository.UserRepository;
import com.abhay.redditclone.repository.VerificationTokenRepository;
import com.abhay.redditclone.security.JwtProvider;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static com.abhay.redditclone.util.Constants.*;

@Service
@AllArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final MailService mailService;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;

    @Transactional
    public void signup(RegisterRequest registerRequest) {
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setCreated(Instant.now());
        user.setEnabled(false);

        userRepository.save(user);

        String token = generateVerificationToken(user);
        String message = "Thank you for signing up to Spring Reddit, " +
                "please click on the below url to activate your account :" +
                ACTIVATION_EMAIL + token;
        mailService.sendMail(
                new NotificationEmail("Please Activate your Account",
                        user.getEmail(), message));
    }

    private String generateVerificationToken(User user) {
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);
        verificationTokenRepository.save(verificationToken);
        return token;
    }

    public void verifyAccount(String token) {
        Optional<VerificationToken> verificationToken =
                verificationTokenRepository.findByToken(token);
        verificationToken
                .orElseThrow(() -> new SpringRedditException("Invalid Token"));
        fetchUserAndEnable(verificationToken.get());
    }

    @Transactional
    private void fetchUserAndEnable(VerificationToken verificationToken) {
//        String username = verificationToken.getUser().getUsername();
//        User user = userRepository.findByUsername(username).orElseThrow(
//                () -> new SpringRedditException(
//                        "User not found with name - " + username));
        User user = verificationToken.getUser();
        user.setEnabled(true);
        userRepository.save(user);
    }

    public AuthenticationResponse login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtProvider.generateToken(authentication);
        return new AuthenticationResponse(token, loginRequest.getUsername());
    }
}
