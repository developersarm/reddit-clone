package com.abhay.redditclone.repository;

import com.abhay.redditclone.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VerificationTokenRepository
        extends JpaRepository<VerificationToken, Long> {
    Optional<VerificationToken> findByToken(String token);
}
