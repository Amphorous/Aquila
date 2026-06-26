package org.hoyo.aquila.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserRegistryService {

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    private static final String REGISTERED_USERS_KEY = "userInfo:registeredKeys";
    private static final String BINDINGS_KEY_PREFIX = "userBindings:";
    private static final String GAMES_INDEX_SUFFIX = ":games";

    /**
     * Registers a user in the set of known users upon successful Discord login.
     *
     * @param ENCRYPTED_KEY The unique identifier from any future auth source.
     * @return Mono<Boolean> true if newly registered, false if they already existed.
     */
    public Mono<Boolean> registerUserLogin(String ENCRYPTED_KEY) {
        return redisTemplate.opsForSet().add(REGISTERED_USERS_KEY, ENCRYPTED_KEY)
                .map(added -> added > 0)
                .doOnSuccess(wasInserted -> {
                    if (Boolean.TRUE.equals(wasInserted)) {
                        log.info("User registry initialized for ENCRYPTED_KEY: {}", ENCRYPTED_KEY);
                    }
                })
                .doOnError(e -> log.error("Failed to register user login for {}: {}", ENCRYPTED_KEY, e.getMessage()));
    }

    /**
     * Links a validated UID to a specific game for a user.
     * Stored as a Redis set at "userBindings:{ENCRYPTED_KEY}:{game}", with the game name added
     * to the "userBindings:{ENCRYPTED_KEY}:games" index set so it can be discovered later.
     *
     * @param ENCRYPTED_KEY The unique user identifier.
     * @param game The game identifier (e.g., "hsr", "genshin").
     * @param uid The game-specific UID.
     * @return Mono<Void>
     */
    public Mono<Void> linkValidatedUid(String ENCRYPTED_KEY, String game, String uid) {
        return redisTemplate.opsForSet().add(bindingsKey(ENCRYPTED_KEY, game), uid)
                .then(redisTemplate.opsForSet().add(gamesIndexKey(ENCRYPTED_KEY), game))
                .doOnSuccess(v -> log.info("Linked {} UID [{}] to user {}", game, uid, ENCRYPTED_KEY))
                .then();
    }

    /**
     * Retrieves all game UIDs associated with a user.
     *
     * @param ENCRYPTED_KEY The unique identifier from Discord.
     * @return Mono<Map<String, Set<String>>> A map of game names to sets of UIDs.
     */
    public Mono<Map<String, Set<String>>> getUserGameMappings(String ENCRYPTED_KEY) {
        return redisTemplate.opsForSet().members(gamesIndexKey(ENCRYPTED_KEY))
                .flatMap(game -> redisTemplate.opsForSet().members(bindingsKey(ENCRYPTED_KEY, game))
                        .collect(Collectors.toCollection(LinkedHashSet::new))
                        .map(uids -> Map.<String, Set<String>>entry(game, uids)))
                .collectMap(Map.Entry::getKey, Map.Entry::getValue);
    }

    private String gamesIndexKey(String encryptedKey) {
        return BINDINGS_KEY_PREFIX + encryptedKey + GAMES_INDEX_SUFFIX;
    }

    private String bindingsKey(String encryptedKey, String game) {
        return BINDINGS_KEY_PREFIX + encryptedKey + ":" + game;
    }
}
