package tech.buildrun.springsecurity.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import tech.buildrun.springsecurity.entities.Tweet;

import java.util.UUID;

@Repository
public interface TweetRepository extends JpaRepository<Tweet, Long> {

    @Query("SELECT t FROM Tweet t WHERE t.user.userId = :userId ORDER BY t.creationTimestamp DESC")
    Page<Tweet> findByUserUserId(@Param("userId") UUID userId, Pageable pageable);
}