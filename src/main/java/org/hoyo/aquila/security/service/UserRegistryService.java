package org.hoyo.aquila.security.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Lygus System Architecture: User Registry Service
 * Responsibility: Manages the 'userInfo' Redis collection for cross-game UID mapping.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserRegistryService {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    private static final String USER_INFO_HASH_KEY = "userInfo";

    /**
     * Initializes a user entry in the 'userInfo' hash upon successful Discord login.
     *
     * @param discordId The unique identifier from Discord.
     * @return Mono<Boolean> true if initialized successfully, false if they already existed.
     */
    public Mono<Boolean> registerUserLogin(String discordId) {
        return redisTemplate.opsForHash()
                .putIfAbsent(USER_INFO_HASH_KEY, discordId, "{}")
                .doOnSuccess(wasInserted -> {
                    if (Boolean.TRUE.equals(wasInserted)) {
                        log.info("User registry initialized for Discord ID: {}", discordId);
                    }
                })
                .doOnError(e -> log.error("Failed to register user login for {}: {}", discordId, e.getMessage()));
    }

    /**
     * Links a validated UID to a specific game for a user.
     *
     * @param discordId The unique identifier from Discord.
     * @param game The game identifier (e.g., "hsr", "genshin").
     * @param uid The game-specific UID.
     * @return Mono<Void>
     */
    public Mono<Void> linkValidatedUid(String discordId, String game, String uid) {
        return redisTemplate.opsForHash().get(USER_INFO_HASH_KEY, discordId)
                .map(Object::toString)
                .defaultIfEmpty("{}") // FIX: Prevents the Mono from swallowing the execution if the user doesn't exist
                .flatMap(this::parseJsonToMap)
                .flatMap(data -> updateJsonWithUid(data, game, uid))
                .flatMap(updatedJson -> redisTemplate.opsForHash()
                        .put(USER_INFO_HASH_KEY, discordId, updatedJson))
                .doOnSuccess(v -> log.info("Linked {} UID [{}] to user {}", game, uid, discordId))
                .then();
    }

    /**
     * Retrieves all game UIDs associated with a user.
     *
     * @param discordId The unique identifier from Discord.
     * @return Mono<Map<String, Set<String>>> A map of game names to sets of UIDs.
     */
    public Mono<Map<String, Set<String>>> getUserGameMappings(String discordId) {
        return redisTemplate.opsForHash().get(USER_INFO_HASH_KEY, discordId)
                .map(Object::toString)
                .flatMap(this::parseJsonToMap)
                .defaultIfEmpty(new HashMap<>());
    }

    /**
     * Internal logic to manipulate the data map and serialize it back to JSON.
     */
    private Mono<String> updateJsonWithUid(Map<String, Set<String>> data, String game, String uid) {
        return Mono.fromCallable(() -> {
            // FIX: Using LinkedHashSet prevents duplicate UIDs while maintaining insertion order
            data.computeIfAbsent(game, k -> new LinkedHashSet<>()).add(uid);
            return objectMapper.writeValueAsString(data);
        }).onErrorMap(JsonProcessingException.class, e ->
                new RuntimeException("Failed to serialize user data to JSON", e)
        );
    }

    /**
     * Safely parses the JSON string into a Map containing Sets.
     */
    private Mono<Map<String, Set<String>>> parseJsonToMap(String json) {
        return Mono.fromCallable(() ->
                objectMapper.readValue(json, new TypeReference<Map<String, Set<String>>>() {})
        ).onErrorResume(e -> {
            // FIX: We throw an error instead of returning {} to prevent accidentally wiping out a user's profile if parsing fails.
            log.error("Error parsing user JSON from Redis. Data might be corrupt: {}", e.getMessage());
            return Mono.error(new IllegalStateException("Corrupt JSON data in Redis", e));
        });
    }
}