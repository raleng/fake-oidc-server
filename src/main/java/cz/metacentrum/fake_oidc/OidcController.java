package cz.metacentrum.fake_oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.MediaTypeEditor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Implementation of all necessary OIDC endpoints.
 *
 * @author Martin Kuba makub@ics.muni.cz
 */
@RestController
public class OidcController {

    private static final Logger log = LoggerFactory.getLogger(OidcController.class);

    public static final String METADATA_ENDPOINT = "/.well-known/openid-configuration";
    public static final String AUTHORIZATION_ENDPOINT = "/authorize";
    public static final String TOKEN_ENDPOINT = "/token";
    public static final String USERINFO_ENDPOINT = "/userinfo";
    public static final String JWKS_ENDPOINT = "/jwks";
    public static final String INTROSPECTION_ENDPOINT = "/introspect";

    private JWSSigner signer;
    private JWKSet publicJWKSet;
    private JWSHeader jwsHeader;

    private final Map<String, AccessTokenInfo> accessTokens = new HashMap<>();
    private final Map<String, CodeInfo> authorizationCodes = new HashMap<>();
    private final SecureRandom random = new SecureRandom();

    private final FakeOidcServerProperties serverProperties;

    public OidcController(@Autowired FakeOidcServerProperties serverProperties) {
        this.serverProperties = serverProperties;
    }

    @PostConstruct
    public void init() throws IOException, ParseException, JOSEException {
        log.info("initializing JWK");
        JWKSet jwkSet = JWKSet.load(getClass().getResourceAsStream("/jwks.json"));
        JWK key = jwkSet.getKeys().get(0);
        signer = new RSASSASigner((RSAKey) key);
        publicJWKSet = jwkSet.toPublicJWKSet();
        jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build();
        log.info("config {}", serverProperties);
    }

    /**
     * Provides OIDC metadata. See the spec at
     * https://openid.net/specs/openid-connect-discovery-1_0.html
     */
    @RequestMapping(value = METADATA_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<?> metadata(UriComponentsBuilder uriBuilder, HttpServletRequest req) {
        log.info("called " + METADATA_ENDPOINT + " from {}", req.getRemoteHost());
        String urlPrefix = uriBuilder.replacePath(null).build().encode().toUriString();
        Map<String, Object> m = new LinkedHashMap<>();
        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        // https://tools.ietf.org/html/rfc8414#section-2
        m.put("issuer", urlPrefix + "/"); // REQUIRED
        m.put("authorization_endpoint", urlPrefix + AUTHORIZATION_ENDPOINT); // REQUIRED
        m.put("token_endpoint", urlPrefix + TOKEN_ENDPOINT); // REQUIRED unless only the Implicit Flow is used
        m.put("userinfo_endpoint", urlPrefix + USERINFO_ENDPOINT); // RECOMMENDED
        m.put("jwks_uri", urlPrefix + JWKS_ENDPOINT); // REQUIRED
        m.put("introspection_endpoint", urlPrefix + INTROSPECTION_ENDPOINT);
        m.put("scopes_supported", Arrays.asList("openid", "profile", "email")); // RECOMMENDED
        m.put("response_types_supported", Arrays.asList("id_token token", "code")); // REQUIRED
        m.put("grant_types_supported", Arrays.asList("authorization_code", "implicit")); // OPTIONAL
        m.put("subject_types_supported", Collections.singletonList("public")); // REQUIRED
        m.put("id_token_signing_alg_values_supported", Arrays.asList("RS256", "none")); // REQUIRED
        m.put("claims_supported",
                Arrays.asList("sub", "iss", "name", "family_name", "given_name", "preferred_username", "email"));
        m.put("code_challenge_methods_supported", Arrays.asList("plain", "S256")); // PKCE support advertised
        return ResponseEntity.ok().body(m);
    }

    /**
     * Provides JSON Web Key Set containing the public part of the key used to sign
     * ID tokens.
     */
    @RequestMapping(value = JWKS_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<String> jwks(HttpServletRequest req) {
        log.info("called " + JWKS_ENDPOINT + " from {}", req.getRemoteHost());
        return ResponseEntity.ok().body(publicJWKSet.toString());
    }

    /**
     * Provides claims about a user. Requires a valid access token.
     */
    @RequestMapping(value = USERINFO_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin(allowedHeaders = { "Authorization", "Content-Type" })
    public ResponseEntity<?> userinfo(@RequestHeader("Authorization") String auth,
            @RequestParam(required = false) String access_token,
            HttpServletRequest req) {
        log.info("called " + USERINFO_ENDPOINT + " from {}", req.getRemoteHost());
        if (!auth.startsWith("Bearer ")) {
            if (access_token == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No token");
            }
            auth = access_token;
        } else {
            auth = auth.substring(7);
        }
        AccessTokenInfo accessTokenInfo = accessTokens.get(auth);
        if (accessTokenInfo == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("access token not found");
        }
        Set<String> scopes = setFromSpaceSeparatedString(accessTokenInfo.scope);
        Map<String, Object> m = new LinkedHashMap<>();
        User user = accessTokenInfo.user;
        m.put("sub", user.getSub());
        if (scopes.contains("profile")) {
            m.put("name", user.getName());
            m.put("family_name", user.getFamily_name());
            m.put("given_name", user.getGiven_name());
            m.put("preferred_username", user.getPreferred_username());
        }
        if (scopes.contains("email")) {
            m.put("email", user.getEmail());
        }
        return ResponseEntity.ok().body(m);
    }

    /**
     * Provides information about a supplied access token.
     */
    @RequestMapping(value = INTROSPECTION_ENDPOINT, method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> introspection(@RequestParam String token,
            @RequestHeader("Authorization") String auth,
            HttpServletRequest req) {
        log.info("called " + INTROSPECTION_ENDPOINT + " from {}", req.getRemoteHost());
        Map<String, Object> m = new LinkedHashMap<>();
        AccessTokenInfo accessTokenInfo = accessTokens.get(token);
        if (accessTokenInfo == null) {
            log.error("token not found in memory: {}", token);
            m.put("active", false);
        } else {
            log.info("found token for user {}, releasing scopes: {}", accessTokenInfo.user.getSub(),
                    accessTokenInfo.scope);
            // see https://tools.ietf.org/html/rfc7662#section-2.2 for all claims
            m.put("active", true);
            m.put("scope", accessTokenInfo.scope);
            m.put("client_id", accessTokenInfo.clientId);
            m.put("username", accessTokenInfo.user.getSub());
            m.put("token_type", "Bearer");
            m.put("exp", accessTokenInfo.expiration.toInstant().toEpochMilli());
            m.put("sub", accessTokenInfo.user.getSub());
            m.put("iss", accessTokenInfo.iss);
        }
        return ResponseEntity.ok().body(m);
    }

    /**
     * Provides token endpoint.
     */
    @RequestMapping(value = TOKEN_ENDPOINT, method = RequestMethod.POST, consumes = "*/*", produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<?> token(@RequestParam Map<String, String> body)
            throws NoSuchAlgorithmException, JOSEException {
        log.info("called " + TOKEN_ENDPOINT);
        String grant_type = body.get("grant_type");
        String code = body.get("code");
        String redirect_uri = body.get("redirect_uri");
        log.info("called " + TOKEN_ENDPOINT + ", grant_type={} code={} redirect_uri={} body={}", grant_type, code,
                redirect_uri, body);
        if (!"authorization_code".equals(grant_type)) {
            return jsonError("unsupported_grant_type", "grant_type is not authorization_code");
        }
        CodeInfo codeInfo = authorizationCodes.get(code);
        if (codeInfo == null) {
            return jsonError("invalid_grant", "code not valid");
        }
        if (!redirect_uri.equals(codeInfo.redirect_uri)) {
            return jsonError("invalid_request", "redirect_uri not valid");
        }
        Map<String, String> map = new LinkedHashMap<>();
        String accessToken = createAccessToken(codeInfo.iss, codeInfo.user, codeInfo.client_id, codeInfo.scope);
        map.put("access_token", accessToken);
        map.put("token_type", "Bearer");
        map.put("expires_in", String.valueOf(serverProperties.getTokenExpirationSeconds()));
        map.put("scope", codeInfo.scope);
        map.put("id_token", createIdToken(codeInfo.iss, codeInfo.user, codeInfo.client_id, codeInfo.givenName,
                codeInfo.familyName, codeInfo.nonce, accessToken));
        return ResponseEntity.ok(map);
    }

    /**
     * Provides authorization endpoint.
     */
    @RequestMapping(value = AUTHORIZATION_ENDPOINT, method = RequestMethod.GET)
    public ResponseEntity<?> authorize(@RequestParam String client_id,
            @RequestParam String redirect_uri,
            @RequestParam String response_type,
            @RequestParam String scope,
            @RequestParam String state,
            @RequestParam String givenName,
            @RequestParam String familyName,
            @RequestParam(required = false) String nonce,
            @RequestParam(required = false) String code_challenge,
            @RequestParam(required = false) String code_challenge_method,
            @RequestParam(required = false) String response_mode,
            // @RequestHeader(name = "Authorization", required = false) String auth,
            UriComponentsBuilder uriBuilder,
            HttpServletRequest req) throws JOSEException, NoSuchAlgorithmException {
        log.info(
                "called " + AUTHORIZATION_ENDPOINT + " from {}, scope={} response_type={} client_id={} redirect_uri={}",
                req.getRemoteHost(), scope, response_type, client_id, redirect_uri);
        // if (auth == null) {
        // log.info("user and password not provided");
        // return response401();
        // } else {
        // String[] creds = new String(Base64.getDecoder().decode(auth.split("
        // ")[1])).split(":", 2);
        // String login = creds[0];
        // String password = creds[1];
        for (User user : serverProperties.getUsers().values()) {
            if (user.getLogname().equals("perun")) {
                log.info("password for user {} is correct", "perun");
                Set<String> responseType = setFromSpaceSeparatedString(response_type);
                String iss = uriBuilder.replacePath("/").build().encode().toUriString();
                if (responseType.contains("token")) {
                    // implicit flow
                    log.info("using implicit flow");
                    String access_token = createAccessToken(iss, user, client_id, scope);
                    String id_token = createIdToken(iss, user, client_id, givenName, familyName, nonce, access_token);
                    String url = redirect_uri + "#" +
                            "access_token=" + urlencode(access_token) +
                            "&token_type=Bearer" +
                            "&state=" + urlencode(state) +
                            "&expires_in=" + serverProperties.getTokenExpirationSeconds() +
                            "&id_token=" + urlencode(id_token);
                    return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
                } else if (responseType.contains("code")) {
                    // authorization code flow
                    log.info("using authorization code flow {}", code_challenge != null ? "with PKCE" : "");
                    String code = createAuthorizationCode(code_challenge, code_challenge_method, client_id,
                            givenName,
                            familyName, redirect_uri, user, iss, scope, nonce);
                    String url = redirect_uri + "?" +
                            "code=" + code +
                            "&state=" + state;
                    return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
                } else {
                    String url = redirect_uri + "#" + "error=unsupported_response_type";
                    return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
                }
            }
        }
        return response401();
        // }
    }

    private String createAuthorizationCode(String code_challenge, String code_challenge_method, String client_id,
            String client_name, String client_password, String redirect_uri, User user, String iss, String scope,
            String nonce) {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        String code = Base64URL.encode(bytes).toString();
        log.info("issuing code={}", code);
        authorizationCodes.put(code, new CodeInfo(code_challenge, code_challenge_method, code, client_id, client_name,
                client_password, redirect_uri, user, iss, scope, nonce));
        return code;
    }

    private String createAccessToken(String iss, User user, String client_id, String scope) throws JOSEException {
        // create JWT claims
        Date expiration = new Date(System.currentTimeMillis() + serverProperties.getTokenExpirationSeconds() * 1000L);
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getSub())
                .issuer(iss)
                .audience(client_id)
                .issueTime(new Date())
                .expirationTime(expiration)
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", scope)
                .build();
        // create JWT token
        SignedJWT jwt = new SignedJWT(jwsHeader, jwtClaimsSet);
        // sign the JWT token
        jwt.sign(signer);
        String access_token = jwt.serialize();
        accessTokens.put(access_token, new AccessTokenInfo(user, access_token, expiration, scope, client_id, iss));
        return access_token;
    }

    private String createIdToken(String iss, User user, String client_id, String givenName, String familyName,
            String nonce, String accessToken) throws NoSuchAlgorithmException, JOSEException {
        // compute at_hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.reset();
        digest.update(accessToken.getBytes(StandardCharsets.UTF_8));
        byte[] hashBytes = digest.digest();
        byte[] hashBytesLeftHalf = Arrays.copyOf(hashBytes, hashBytes.length / 2);
        Base64URL encodedHash = Base64URL.encode(hashBytesLeftHalf);
        final String image = "data:image/png;base64,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";
        // create JWT claims
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getSub())
                .issuer(iss)
                .audience(client_id)
                .issueTime(new Date())
                .expirationTime(
                        new Date(System.currentTimeMillis() + serverProperties.getTokenExpirationSeconds() * 1000L))
                .jwtID(UUID.randomUUID().toString())
                .claim("nonce", nonce)
                .claim("at_hash", encodedHash)
                .claim("givenName", givenName)
                .claim("familyName", familyName)
                .claim("image", image)
                .build();
        // create JWT token
        SignedJWT myToken = new SignedJWT(jwsHeader, jwtClaimsSet);
        // sign the JWT token
        myToken.sign(signer);
        return myToken.serialize();
    }

    private static String urlencode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static ResponseEntity<String> response401() {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.TEXT_HTML);
        responseHeaders.add("WWW-Authenticate", "Basic realm=\"Fake OIDC server\"");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).headers(responseHeaders)
                .body("<html><body><h1>401 Unauthorized</h1>Fake OIDC server</body></html>");
    }

    private static class AccessTokenInfo {
        final User user;
        final String accessToken;
        final Date expiration;
        final String scope;
        final String clientId;
        final String iss;

        public AccessTokenInfo(User user, String accessToken, Date expiration, String scope, String clientId,
                String iss) {
            this.user = user;
            this.accessToken = accessToken;
            this.expiration = expiration;
            this.scope = scope;
            this.clientId = clientId;
            this.iss = iss;
        }

    }

    private static class CodeInfo {
        final String codeChallenge;
        final String codeChallengeMethod;
        final String code;
        final String client_id;
        final String givenName;
        final String familyName;
        final String redirect_uri;
        final User user;
        final String iss;
        final String scope;
        final String nonce;

        public CodeInfo(String codeChallenge, String codeChallengeMethod, String code, String client_id,
                String givenName, String familyName, String redirect_uri, User user, String iss, String scope,
                String nonce) {
            this.codeChallenge = codeChallenge;
            this.codeChallengeMethod = codeChallengeMethod;
            this.code = code;
            this.client_id = client_id;
            this.givenName = givenName;
            this.familyName = familyName;
            this.redirect_uri = redirect_uri;
            this.user = user;
            this.iss = iss;
            this.scope = scope;
            this.nonce = nonce;
        }
    }

    private static Set<String> setFromSpaceSeparatedString(String s) {
        if (s == null || s.isBlank())
            return Collections.emptySet();
        return new HashSet<>(Arrays.asList(s.split(" ")));
    }

    private static ResponseEntity<?> jsonError(String error, String error_description) {
        log.warn("error={} error_description={}", error, error_description);
        Map<String, String> map = new LinkedHashMap<>();
        map.put("error", error);
        map.put("error_description", error_description);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(map);
    }

}
