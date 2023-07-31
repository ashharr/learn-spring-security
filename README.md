# Securing Spring Boot Applications with Spring Security

Security is the NO 1 priority for enterprises today!

What is the most popular security project in the
Spring eco-system?

Spring Security: Protect your web applications, REST API and
microservices
Spring Security can be difficult to get started
Filter Chain
Authentication managers
Authentication providers
...

BUT it provides a very flexible security system!
By default, everything is protected!
A chain of filters ensure proper authentication and authorization

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c8dac76f-1740-41cf-8c1a-7de0ce94b04d/Untitled.png)

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/0bd58340-8bef-44f4-9f53-4c811d7b2339/Untitled.png)

Form login is by default enabled for which username is “user” by default

we can disable it from the SBWSC security filter chain method

A CSRF token is generated for all write request (POST,PUT)

we can also likewise disable it

```java
package com.springboot.learnspringsecurity.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class BasicAuthSecurityConfiguration {
	

	@Bean
	@Order(SecurityProperties.BASIC_AUTH_ORDER)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.httpBasic(withDefaults());
		http.authorizeHttpRequests(
				auth -> {
					auth.anyRequest().authenticated();
				});
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		
		

//		http.formLogin(withDefaults());
		
		http.csrf().disable();
		return http.build();
	}
	
	
}
```

Creating our own in memory user

// BasicAuthSecurityConfiguration.java

```java
@Bean
	public UserDetailsService userDetailService() {
		
		var user = User.withUsername("ashharr")
			.password("{noop}spring")
			.roles("USER")
			.build();

		
		var admin = User.withUsername("admin")
				.password("{noop}dummy")
				.roles("ADMIN")
				.build();

		return new InMemoryUserDetailsManager(user, admin);
	}
```

Now we dont need to specify username and pass in the application.properties

Storing User credentials in DB usin JDBC + h2

```java
package com.springboot.learnspringsecurity.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class BasicAuthSecurityConfiguration {
	

	@Bean
	@Order(SecurityProperties.BASIC_AUTH_ORDER)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.httpBasic(withDefaults());
		http.authorizeHttpRequests(
				auth -> {
					auth.anyRequest().authenticated();
				});
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.headers().frameOptions().sameOrigin();
		

//		http.formLogin(withDefaults());
		
		http.csrf().disable();
		return http.build();
	}
	
//	@Bean
//	public UserDetailsService userDetailService() {
//		
//		var user = User.withUsername("ashharr")
//			.password("{noop}spring")
//			.roles("USER")
//			.build();
//
//		
//		var admin = User.withUsername("admin")
//				.password("{noop}dummy")
//				.roles("ADMIN")
//				.build();
//
//		return new InMemoryUserDetailsManager(user, admin);
//	}
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}
	
	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		var user = User.withUsername("ashharr")
			.password("{noop}spring")
			.roles("USER")
			.build();
		
		var admin = User.withUsername("admin")
				.password("{noop}spring")
				.roles("ADMIN", "USER")
				.build();
		
		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return jdbcUserDetailsManager;
	}
}
```

`spring.datasource.url=jdbc:h2:mem:testdb`

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/1d427cbb-8df5-43e6-8df3-c8a8f5fcfe18/Untitled.png)

Storing password as encoded

Available encoding methods

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/4099d92f-ce65-4d3a-8fa6-2b62b74d0d51/Untitled.png)

```java
@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		var user = User.withUsername("ashharr")
//			.password("{noop}spring")
				.password("spring")
				.passwordEncoder(str -> passwordEncoder().encode(str))
			.roles("USER")
			.build();
		
		var admin = User.withUsername("admin")
//				.password("{noop}spring")
				.password("spring")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				.roles("ADMIN", "USER")
				.build();
		
		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return jdbcUserDetailsManager;
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
```

## Making use of JWT Authentication

It makes use of assymetric encryption alsoc alled as public key cryptography.

### Symmetric Key Encryption

Symmetric encryption algorithms use the same key for encryption and
decryption

### Asymmetric Key Encryption

Two Keys : Public Key and Private Key
Also called Public Key Cyptography
Encrypt data with Public Key and
decrypt with Private Key
Share Public Key with everybody and
keep the Private Key with you(YEAH,
ITS PRIVATE!)
No crazy questions:
Will somebody not figure out private key
using the public key?
Best Practice: Use Asymmetric Keys

### Understanding High Level JWT Flow

1: Create a JWT
Needs Encoding
   1: User credentials
   2: User data (payload)
   3: RSA key pair
We will create a JWT Resource for creating JWT later
2: Send JWT as part of request header
Authorization Header
Bearer Token
Authorization: Bearer ${JWT_TOKEN}
3: JWT is verified
Needs Decoding
RSA key pair (Public Key)

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9b3f2297-5c1e-4a9f-b3c2-098853dfc518/Untitled.png)

## Getting Started with JWT Security Configuration

JWT Authentication using Spring Boot’s OAuth2
Resource Server
**1: Create Key Pair**
We will use java.security.KeyPairGenerator
You can use openssl as well
**2: Create RSA Key object using Key Pair**
com.nimbusds.jose.jwk.RSAKey
**3: Create JWKSource (JSON Web Key source)**
Create JWKSet (a new JSON Web Key set) with the RSA Key
Create JWKSource using the JWKSet
**4: Use RSA Public Key for Decoding**
NimbusJwtDecoder.withPublicKey(rsaKey().toRSAPublicKey()).build()
**5: Use JWKSource for Encoding**
return new NimbusJwtEncoder(jwkSource());
We will use this later in the JWT Resource

```java
package com.springboot.learnspringsecurity.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class JwtSecurityConfiguration {
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http.httpBasic(withDefaults());
		http.authorizeHttpRequests(
				auth -> {
					auth.anyRequest().authenticated();
				});
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.headers().frameOptions().sameOrigin();
		
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//		http.formLogin(withDefaults());
		
		http.csrf().disable();
		return http.build();
	}
	
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}
	
	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		var user = User.withUsername("in28minutes")
			//.password("{noop}dummy")
			.password("dummy")
			.passwordEncoder(str -> passwordEncoder().encode(str))
			.roles("USER")
			.build();
		
		var admin = User.withUsername("admin")
				//.password("{noop}dummy")
				.password("dummy")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				.roles("ADMIN", "USER")
				.build();
		
		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return jdbcUserDetailsManager;
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public KeyPair keyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		
		return new RSAKey
				.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString())
				.build();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwkSet = new JWKSet(rsaKey);
		
		return (jwkSelector, context) ->  jwkSelector.select(jwkSet);
		
	}
	
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder
				.withPublicKey(rsaKey.toRSAPublicKey())
				.build();
		
	}
	
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
}
```

Now the decoding part is done using RSA key pair

We will create the encoding code now using JWT resource

[JwtSecurityConfiguration.java](http://JwtSecurityConfiguration.java) (encoder added)

Also First disable Basic Auth config by commenting @Configuration

```java
package com.springboot.learnspringsecurity.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class JwtSecurityConfiguration {
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http.httpBasic(withDefaults());
		http.authorizeHttpRequests(
				auth -> {
					auth.anyRequest().authenticated();
				});
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.headers().frameOptions().sameOrigin();
		
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
//		http.formLogin(withDefaults());
		
		http.csrf().disable();
		return http.build();
	}
	
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}
	
	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		var user = User.withUsername("ashharr")
			//.password("{noop}dummy")
			.password("spring")
			.passwordEncoder(str -> passwordEncoder().encode(str))
			.roles("USER")
			.build();
		
		var admin = User.withUsername("admin")
				//.password("{noop}dummy")
				.password("spring")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				.roles("ADMIN", "USER")
				.build();
		
		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return jdbcUserDetailsManager;
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public KeyPair keyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		
		return new RSAKey
				.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString())
				.build();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwkSet = new JWKSet(rsaKey);
		
		return (jwkSelector, context) ->  jwkSelector.select(jwkSet);
		
	}
	
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder
				.withPublicKey(rsaKey.toRSAPublicKey())
				.build();
		
	}
	
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
	
}
```

[JwtAuthenticationResource.java](http://JwtAuthenticationResource.java) will generate the JWT auth token

```java
package com.springboot.learnspringsecurity.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtAuthenticationResource {
	
private JwtEncoder jwtEncoder;
	
	public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}
	
	@PostMapping("/authenticate") 
	public JwtResponse authenticate(Authentication authentication) {
		return new JwtResponse(createToken(authentication));
	}

	private String createToken(Authentication authentication) {
		var claims = JwtClaimsSet.builder()
								.issuer("self")
								.issuedAt(Instant.now())
								.expiresAt(Instant.now().plusSeconds(60 * 30))
								.subject(authentication.getName())
								.claim("scope", createScope(authentication))
								.build();
		
		return jwtEncoder.encode(JwtEncoderParameters.from(claims))
						.getTokenValue();
	}

	private String createScope(Authentication authentication) {
		return authentication.getAuthorities().stream()
			.map(a -> a.getAuthority())
			.collect(Collectors.joining(" "));			
	}

}

record JwtResponse(String token) {}
```

## Understanding Spring Security Authentication

Authentication is done as part of the Spring Security Filter
Chain!
1: AuthenticationManager - Responsible for authentication
Can interact with multiple authentication providers
2: AuthenticationProvider - Perform specific authentication
type
JwtAuthenticationProvider - JWT Authentication
3: UserDetailsService - Core interface to load user data
How is authentication result stored?
SecurityContextHolder > SecurityContext > Authentication >
GrantedAuthority
Authentication - (After authentication) Holds user (Principal) details
GrantedAuthority - An authority granted to principal (roles, scopes,..)

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/114608a0-924d-4438-9b98-f54a75b5cbd8/Untitled.png)

1: Global Security: authorizeHttpRequests
.requestMatchers("/users").hasRole("USER")
hasRole, hasAuthority, hasAnyAuthority, isAuthenticated
2: Method Security (@EnableMethodSecurity)
**@Pre and @Post Annotations**
@PreAuthorize("hasRole('USER') and #username == [authentication.name](http://authentication.name/)")
@PostAuthorize("returnObject.username == 'in28minutes'")
**JSR-250 annotations**
@EnableMethodSecurity(jsr250Enabled = true)
@RolesAllowed({"ADMIN","USER"})
@Secured annotation
@EnableMethodSecurity(securedEnabled = true)
@Secured({"ADMIN","USER"})

Pre and post auth is recommended for a resource