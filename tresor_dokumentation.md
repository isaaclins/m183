# Tresor-Anwendung: Authentifizierung und Autorisierung - Technische Dokumentation

## Übersicht

Diese Dokumentation zeigt die verschiedenen Authentifizierungs- und Autorisierungsmechanismen der Tresor-Anwendung und erklärt, wo im Code diese implementiert sind.

## 1. Login mit Email und Passwort

### Frontend Implementation (LoginUser.js)

Der Login-Prozess beginnt im Frontend in der Datei `LoginUser.js`:

```javascript
// 183_12_2_tresorfrontend_rupe-master/src/pages/user/LoginUser.js
const handleSubmit = async (e) => {
  e.preventDefault();
  console.log("Submitting login data:", loginValues);

  try {
    const response = await fetch("http://localhost:8080/api/users/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: loginValues.email,
        password: loginValues.password,
        mfaToken: loginValues.mfaToken,
      }),
    });

    console.log("Response status:", response.status);
    const data = await response.json();

    if (response.ok) {
      console.log("Login successful:", data);
      // Speichere Token und User-Daten in localStorage
      localStorage.setItem("userId", data.userId);
      localStorage.setItem("userEmail", data.email);
      localStorage.setItem("token", data.token);
      localStorage.setItem("password", loginValues.password);
      localStorage.setItem("isLoggedIn", "true");
      navigate("/");
    }
  } catch (error) {
    console.error("Error during login:", error);
    setErrorMessage("An error occurred during login. Please try again.");
  }
};
```

### Backend Implementation (UserController.java)

Der Backend-Login-Endpoint verarbeitet die Authentifizierung:

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/controller/UserController.java
@PostMapping("/login")
public ResponseEntity<String> doLoginUser(@RequestBody LoginUser loginUser, BindingResult bindingResult) {
    logger.info("UserController.doLoginUser: Attempting login for email: {}", loginUser.getEmail());

    // 1. Input validation
    if (bindingResult.hasErrors()) {
        // Validierungsfehler behandeln
        logger.error("UserController.doLoginUser: Validation failed: {}", json);
        return ResponseEntity.badRequest().body(json);
    }

    // 2. Find user by email
    User user = userService.findByEmail(loginUser.getEmail());
    if (user == null) {
        logger.warn("UserController.doLoginUser: No user found with email: {}", loginUser.getEmail());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(json);
    }

    // 3. Verify password
    boolean passwordMatches = passwordService.verifyPassword(loginUser.getPassword(), user.getPassword());
    if (!passwordMatches) {
        logger.warn("UserController.doLoginUser: Password mismatch for user: {}", user.getEmail());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(json);
    }

    // 4. Verify MFA token (2FA)
    if (!user.getMfaSecret().isEmpty() && !TOTPSecretGenerator.verifyToken(user.getMfaSecret(), Integer.parseInt(loginUser.getMfaToken()))) {
        logger.warn("UserController.doLoginUser: Invalid MFA token for user: {}", user.getEmail());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(json);
    }

    // 5. Login successful - Generate JWT Token
    logger.info("UserController.doLoginUser: Login successful for user ID: {}", user.getId());
    String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());

    // 6. Return user data and token
    JsonObject obj = new JsonObject();
    obj.addProperty("token", token);
    obj.addProperty("userId", user.getId());
    obj.addProperty("firstName", user.getFirstName());
    obj.addProperty("lastName", user.getLastName());
    obj.addProperty("email", user.getEmail());

    return ResponseEntity.ok().body(json);
}
```

## 2. User Secrets auflisten

### Frontend Implementation (Secrets.js)

Das Frontend ruft die User-Secrets über eine spezielle API auf:

```javascript
// 183_12_2_tresorfrontend_rupe-master/src/pages/secret/Secrets.js
useEffect(() => {
  const fetchSecrets = async () => {
    setErrorMessage("");
    if (!loginValues.email) {
      console.error(
        "Secrets: No valid email, please do login first:" + loginValues
      );
      setErrorMessage("No valid email, please do login first.");
    } else {
      try {
        const data = await getSecretsforUser(loginValues);
        setSecrets(data);
      } catch (error) {
        console.error("Failed to fetch to server:", error.message);
        setErrorMessage(error.message);
      }
    }
  };
  fetchSecrets();
}, [loginValues]);
```

### API Call (FetchSecrets.js)

Die tatsächliche API-Anfrage erfolgt in `FetchSecrets.js`:

```javascript
// 183_12_2_tresorfrontend_rupe-master/src/comunication/FetchSecrets.js
export const getSecretsforUser = async (loginValues) => {
  try {
    const requestBody = {
      email: loginValues.email,
      encryptPassword: loginValues.password,
    };

    const response = await fetch(`${API_URL}/secrets/byemail`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${localStorage.getItem("token")}`, // JWT Token für Authorization
      },
      body: JSON.stringify(requestBody),
    });

    console.log("Raw response status:", response.status);
    const responseText = await response.text();
    console.log("Raw response body:", responseText);

    if (!response.ok) {
      throw new Error(errorData.message || "Server response failed.");
    }

    let data = JSON.parse(responseText);
    console.log("Secrets successfully retrieved:", data);
    return data;
  } catch (error) {
    console.error("Failed to get secrets:", error);
    throw new Error("Failed to get secrets: " + error.message);
  }
};
```

### Backend Implementation (SecretController.java)

Der Backend-Controller verarbeitet die Secrets-Anfrage:

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/controller/SecretController.java
@PostMapping("/byemail")
public ResponseEntity<List<Secret>> getSecretsByEmail(@RequestBody EncryptCredentials credentials) {
    System.out.println("Yay in the controller");
    System.out.println("SecretController.getSecretsByEmail " + credentials);

    // 1. Find user by email
    User user = userService.findByEmail(credentials.getEmail());

    // 2. Get all secrets for this user
    List<Secret> secrets = secretService.getSecretsByUserId(user.getId());
    if (secrets.isEmpty()) {
        System.out.println("SecretController.getSecretsByEmail secret isEmpty");
        return ResponseEntity.notFound().build();
    }

    // 3. Decrypt content for each secret
    for(Secret secret: secrets) {
        try {
            secret.setContent(new EncryptUtil(credentials.getEncryptPassword()).decrypt(secret.getContent()));
        } catch (EncryptionOperationNotPossibleException e) {
            System.out.println("SecretController.getSecretsByEmail " + e + " " + secret);
            secret.setContent("not encryptable. Wrong password?");
        }
    }

    System.out.println("SecretController.getSecretsByEmail " + secrets);
    return ResponseEntity.ok(secrets);
}
```

## 3. Backend Web Security Konfiguration

### SecurityConfig.java - Zentrale Sicherheitskonfiguration

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/config/SecurityConfig.java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthFilterImpl jwtAuthFilter,
            CustomOAuth2UserServiceImpl oAuth2UserService,
            CustomOAuth2SuccessHandlerImpl oAuth2SuccessHandler) throws Exception {
        http
                // CSRF deaktiviert für development
                .csrf(csrf -> csrf.disable())

                // URL-basierte Autorisierung
                .authorizeHttpRequests(auth -> auth
                        // Öffentliche Endpoints (ohne Authentifizierung)
                        .requestMatchers("/", "/api/users/login", "/api/users/register", "/oauth2/**",
                                "/login/oauth2/code/**", "/api/users/request-password-reset",
                                "/api/users/reset-password")
                        .permitAll()

                        // User Registration erlaubt
                        .requestMatchers(HttpMethod.POST, "/api/users").permitAll()

                        // Secrets nur für USER und ADMIN
                        .requestMatchers("/api/secrets/**").hasAnyRole("USER", "ADMIN")

                        // User-Management nur für ADMIN
                        .requestMatchers(HttpMethod.GET, "/api/users/**").hasRole("ADMIN")

                        // Alle anderen Requests benötigen Authentifizierung
                        .anyRequest().authenticated())

                // OAuth2 Login Configuration
                .oauth2Login(oauth -> oauth
                        .userInfoEndpoint(info -> info.userService(oAuth2UserService))
                        .successHandler(oAuth2SuccessHandler))

                // JWT Filter vor UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // BCrypt für Password-Hashing
    }
}
```

## 4. JWT Token-Erstellung und Authentifizierung

### JWT Token Generierung (JwtUtil.java)

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/util/JwtUtil.java
@Component
public class JwtUtil {
    // Sicherheitsschlüssel (in Produktion aus sicherer Quelle laden)
    private final Key key = Keys.hmacShaKeyFor("your-256-bit-secret-key-here-must-be-long-enough".getBytes(StandardCharsets.UTF_8));
    private final long expirationMs = 86400000; // 24 Stunden

    // JWT Token generieren
    public String generateToken(String subject, String role) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .subject(subject)           // User Email als Subject
                .claim("role", role)        // User Role als Claim
                .issuedAt(now)             // Erstellungszeit
                .expiration(expiryDate)    // Ablaufzeit
                .signWith(key)             // Signierung mit Secret Key
                .compact();
    }

    // Subject (Email) aus Token extrahieren
    public String extractSubject(String token) {
        return parseClaims(token).getPayload().getSubject();
    }

    // Token validieren
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // Role aus Token extrahieren
    public String extractRole(String token) {
        return parseClaims(token).getPayload().get("role", String.class);
    }

    // Token parsen und Claims extrahieren
    private Jws<Claims> parseClaims(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key)
                .build()
                .parseSignedClaims(token);
    }
}
```

### JWT Authentication Filter (JwtAuthFilterImpl.java)

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/impl/JwtAuthFilterImpl.java
@Component
public class JwtAuthFilterImpl extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Öffentliche Pfade definieren, die JWT-Check umgehen
        String path = request.getRequestURI();
        if (path.startsWith("/api/users/login") ||
                path.startsWith("/api/users/register") ||
                path.startsWith("/oauth2") ||
                path.startsWith("/login/oauth2")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // Authorization Header prüfen
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // JWT Token extrahieren (ohne "Bearer " Prefix)
        jwt = authHeader.substring(7);

        try {
            // Username aus JWT extrahieren
            userEmail = jwtUtil.extractSubject(jwt);

            // Wenn Email vorhanden und noch keine Authentifizierung gesetzt
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // User Details laden
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // Token validieren
                if (jwtUtil.validateToken(jwt)) {
                    // Role aus JWT extrahieren
                    String role = jwtUtil.extractRole(jwt);

                    // Authentication Token mit Authorities erstellen
                    List<SimpleGrantedAuthority> authorities = List.of(
                            new SimpleGrantedAuthority("ROLE_" + role));

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, authorities);

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Authentication in Security Context setzen
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            logger.error("JWT Authentication failed", e);
        }

        filterChain.doFilter(request, response);
    }
}
```

## 5. 2FA (Multi-Factor Authentication) Implementation

### TOTP Secret Generation (TOTPSecretGenerator.java)

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/impl/TOTPSecretGenerator.java
public class TOTPSecretGenerator {

    // TOTP Secret generieren (160-bit, Base32 encodiert)
    public static String generateSecret() {
        byte[] buffer = new byte[20]; // 160-bit secret (recommended)
        new SecureRandom().nextBytes(buffer);
        Base32 base32 = new Base32();
        return base32.encodeToString(buffer).replace("=", "");
    }

    // TOTP Token verifizieren
    public static boolean verifyToken(String secret, int code) {
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        return gAuth.authorize(secret, code);
    }
}
```

### User Registration mit MFA Setup

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/controller/UserController.java
@PostMapping
public ResponseEntity<String> createUser(@Valid @RequestBody RegisterUser registerUser, BindingResult bindingResult) {
    // ... Validation und Password-Checks ...

    // User erstellen mit TOTP Secret
    User user = new User(
          null,
          registerUser.getFirstName(),
          registerUser.getLastName(),
          registerUser.getEmail(),
          passwordService.hashPassword(registerUser.getPassword()),
          TOTPSecretGenerator.generateSecret(),  // MFA Secret generieren
          User.Role.USER
          );

    userService.createUser(user);

    // TOTP URI für QR-Code generieren
    JsonObject obj = new JsonObject();
    obj.addProperty("answer", "User Saved");
    obj.addProperty("totpUri", String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
      "TresorApp", user.getEmail(), user.getMfaSecret(), "TresorApp"));

    return ResponseEntity.accepted().body(json);
}
```

### MFA Setup Frontend (SetupMFA.js)

```javascript
// 183_12_2_tresorfrontend_rupe-master/src/pages/user/SetupMFA.js
function SetupMFA() {
  const query = new URLSearchParams(useLocation().search);
  const totpUri = query.get("totpUri");

  if (!totpUri) {
    return <p>Error: TOTP setup link missing.</p>;
  }

  const secret = totpUri.split("secret=")[1].split("&")[0];

  return (
    <div>
      <h2>Multi-Factor Authentication Setup</h2>
      <p>
        Scan this QR code with your Authenticator app (e.g., Google
        Authenticator or Authy):
      </p>
      <QRCodeCanvas value={totpUri} size={200} />
      <p>Or enter this secret manually:</p>
      <code style={{ fontSize: "1.2rem" }}>{secret}</code>
    </div>
  );
}
```

## 6. OAuth2 Implementation (Google Login)

### OAuth2 User Service

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/impl/CustomOAuth2UserServiceImpl.java
@Service
public class CustomOAuth2UserServiceImpl implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        var delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // Google User Info extrahieren
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        // User in DB finden oder erstellen
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setFirstName(name);
                    newUser.setLastName(name);
                    newUser.setRole(User.Role.USER);
                    return userRepository.save(newUser);
                });

        return new DefaultOAuth2User(
            Collections.singleton(new SimpleGrantedAuthority(user.getRole().name())),
            oAuth2User.getAttributes(),
            "email"
        );
    }
}
```

### OAuth2 Success Handler

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/impl/CustomOAuth2SuccessHandlerImpl.java
@Component
public class CustomOAuth2SuccessHandlerImpl implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        var principal = (DefaultOAuth2User) authentication.getPrincipal();
        String email = principal.getAttribute("email");
        String name = principal.getAttribute("name");
        String googleId = principal.getAttribute("sub");

        // User finden oder erstellen
        User user = userRepository.findByEmail(email)
                .orElseGet(() -> createNewUser(email, name, googleId));

        // JWT Token generieren
        String jwt = jwtUtil.generateToken(user.getEmail(), user.getRole().name());

        // Redirect URL mit Token erstellen
        String redirectUrl = UriComponentsBuilder
                .fromUriString("http://localhost:3000/oauth2/redirect")
                .queryParam("token", jwt)
                .queryParam("email", user.getEmail())
                .queryParam("userId", user.getId())
                .queryParam("password", user.getPassword())
                .build().toUriString();

        response.sendRedirect(redirectUrl);
    }
}
```

## 7. Password Hashing und Verschlüsselung

### Password Encryption Service

```java
// 183_12_1_tresorbackend_rupe-master/src/main/java/ch/bbw/pr/tresorbackend/service/PasswordEncryptionService.java
@Service
public class PasswordEncryptionService {

   @Value("${app.security.pepper}")
   private String pepper;

   private static final int BCRYPT_COST = 12;

   // Passwort hashen mit BCrypt und Pepper
   public String hashPassword(String password) {
      String passwordWithPepper = password + pepper;
      return BCrypt.hashpw(passwordWithPepper, BCrypt.gensalt(BCRYPT_COST));
   }

   // Passwort verifizieren
   public boolean verifyPassword(String password, String hashedPassword) {
      String passwordWithPepper = password + pepper;
      return BCrypt.checkpw(passwordWithPepper, hashedPassword);
   }
}
```

## 8. Logging Configuration

Das System verwendet umfassendes Logging für alle wichtigen Operationen:

### Login Logging

```java
logger.info("UserController.doLoginUser: Attempting login for email: {}", loginUser.getEmail());
logger.warn("UserController.doLoginUser: No user found with email: {}", loginUser.getEmail());
logger.warn("UserController.doLoginUser: Password mismatch for user: {}", user.getEmail());
logger.warn("UserController.doLoginUser: Invalid MFA token for user: {}", user.getEmail());
logger.info("UserController.doLoginUser: Login successful for user ID: {}", user.getId());
```

### Secret Operations Logging

```java
System.out.println("SecretController.getSecretsByEmail " + credentials);
System.out.println("SecretController.getSecretsByEmail secret isEmpty");
System.out.println("SecretController.getSecretsByEmail " + secrets);
```

### Frontend Console Logging

```javascript
console.log("Submitting login data:", loginValues);
console.log("Response status:", response.status);
console.log("Login successful:", data);
console.log("Raw response status:", response.status);
console.log("Raw response body:", responseText);
```

## 9. Zusammenfassung der Sicherheitsfeatures

1. **Passwort-Sicherheit**: BCrypt-Hashing mit Pepper und hohem Cost-Factor (12)
2. **JWT-basierte Session-Verwaltung**: Stateless Authentication mit signierten Tokens
3. **2FA/MFA**: TOTP-basierte Zwei-Faktor-Authentifizierung mit Google Authenticator
4. **OAuth2 Integration**: Google Login mit automatischer User-Erstellung
5. **Role-based Authorization**: USER/ADMIN Rollen mit unterschiedlichen Berechtigungen
6. **Captcha-Schutz**: hCaptcha Integration für Registrierung
7. **Password Reset**: Sichere Token-basierte Passwort-Wiederherstellung
8. **Content Encryption**: AES-Verschlüsselung für sensitive Secret-Daten
9. **CORS Configuration**: Sichere Cross-Origin-Konfiguration
10. **Comprehensive Logging**: Ausführliches Logging aller Sicherheitsereignisse

Diese Implementierung zeigt eine moderne, mehrstufige Sicherheitsarchitektur mit verschiedenen Authentifizierungsmethoden und umfassenden Schutzmaßnahmen gegen gängige Sicherheitsbedrohungen.
