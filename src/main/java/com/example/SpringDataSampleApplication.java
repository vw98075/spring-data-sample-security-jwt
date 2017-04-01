package com.example;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.jsonwebtoken.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.webmvc.BasePathAwareController;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.filter.GenericFilterBean;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import javax.persistence.*;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.DecimalMin;
import javax.validation.constraints.Digits;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.IOException;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@SpringBootApplication
@EnableSwagger2
@Import({springfox.documentation.spring.data.rest.configuration.SpringDataRestConfiguration.class,
		springfox.bean.validators.configuration.BeanValidatorPluginsConfiguration.class})
public class SpringDataSampleApplication {

	@Bean
	public Docket api() {
		return new Docket(DocumentationType.SWAGGER_2)
				.select()
				.apis(RequestHandlerSelectors.any())
				.paths(PathSelectors.any())
				.build();
	}

	@Bean
	CommandLineRunner initData(BookRepository bookRepository, AuthorRepository authorRepository, AccountRepository accountRepository){
		return args -> {

			accountRepository.save(new Account("user", "user"));
			accountRepository.save(new Account("admin", "admin", new HashSet<>(Arrays.asList(Account.Role.ROLE_USER, Account.Role.ROLE_ADMIN))));

			SecurityUtils.runAs("system", "system", "ROLE_ADMIN");

			bookRepository.save(new Book("Spring Microservices", "Learn how to efficiently build and implement microservices in Spring," +
						"and how to use Docker and Mesos to push the boundaries. Examine a number of real-world use cases and hands-on code examples." +
						"Distribute your microservices in a completely new way", LocalDate.of(2016, 06, 28), new Money(new BigDecimal(45.83)),
						authorRepository.save(new Author("Felipe", "Gutierrez"))));
			bookRepository.save(new Book("Pro Spring Boot", "A no-nonsense guide containing case studies and best practise for Spring Boot",
						LocalDate.of(2016, 05, 21 ), new Money(new BigDecimal(42.74)),
						authorRepository.save(new Author("Rajesh", "RV"))));
		};
	}

	public static void main(String[] args) {
		SpringApplication.run(SpringDataSampleApplication.class, args);
	}
}

// JWT - Step 1
@Component
class TokenProvider {

	private static final String AUTHORITIES_KEY = "auth";

	private String secretKey = "spring-data-sample";

	public TokenProvider() {}

	public String createToken(UserDetails user) {

		String authorities = user.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(","));

		return Jwts.builder()
				.setSubject(user.getUsername())
				.claim(AUTHORITIES_KEY, authorities)
				.signWith(SignatureAlgorithm.HS256, secretKey)
				.compact();
	}

	public Authentication getAuthentication(String token) {

		Claims claims = Jwts.parser()
				.setSigningKey(secretKey)
				.parseClaimsJws(token)
				.getBody();

		Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());

		User principal = new User(claims.getSubject(), "", authorities);

		return new UsernamePasswordAuthenticationToken(principal, "", authorities);
	}

	public boolean validateToken(String authToken) {
		try {
			Jwts.parser().setSigningKey(secretKey).parseClaimsJws(authToken);
			return true;
		} catch (SignatureException e) {
			System.err.println("Invalid JWT signature: " + e.getMessage());
		} catch (MalformedJwtException e) {
			System.err.println("Invalid JWT token.");
		} catch (ExpiredJwtException e) {
			System.err.println("Expired JWT token.");
		} catch (UnsupportedJwtException e) {
			System.err.println("Unsupported JWT token.");
		} catch (IllegalArgumentException e) {
			System.err.println("JWT token compact of handler are invalid.");
		}
		return false;
	}
}

// JWT - Step 2
@BasePathAwareController
class AccountController {

	private MyUserDetailsService myUserDetailService;

	private TokenProvider tokenProvider;

	public AccountController(MyUserDetailsService myUserDetailService, TokenProvider tokenProvider){
		this.myUserDetailService = myUserDetailService;
		this.tokenProvider = tokenProvider;
	}

	@RequestMapping(value = "/accounts/login", method = RequestMethod.POST)
	public ResponseEntity<String> login(@Valid @RequestBody LoginData login) {

		String userName = login.getUserName();

		try {
			UserDetails user = myUserDetailService.loadUserByUsername(userName);

			if (!BCrypt.checkpw(login.getPassword(), user.getPassword()))
				return new ResponseEntity<>("Invalid login. Please check your username and password.", HttpStatus.UNAUTHORIZED);

			String jwtToken = tokenProvider.createToken(user);
			return new ResponseEntity<>(jwtToken, HttpStatus.OK);

		}catch(UsernameNotFoundException ex){
			return new ResponseEntity<>("The username, " + userName + ", not found", HttpStatus.UNAUTHORIZED);
		}
	}
}

@Data
@AllArgsConstructor
class LoginData{

	@Size(min=1, max=255)
	private String userName;

	@Size(min=1, max=255)
	private String password;
}

// JWT - Step 3
class JWTFilter extends GenericFilterBean {

	private TokenProvider tokenProvider;

	public JWTFilter(TokenProvider tokenProvider) {
		this.tokenProvider = tokenProvider;
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
			throws IOException, ServletException {
		try {
			HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
			String jwt = resolveToken(httpServletRequest);
			if (StringUtils.hasText(jwt) && this.tokenProvider.validateToken(jwt)) {
				Authentication authentication = this.tokenProvider.getAuthentication(jwt);
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
			filterChain.doFilter(servletRequest, servletResponse);
		} catch (ExpiredJwtException eje) {
			System.err.println("Security exception for user " +	eje.getClaims().getSubject() + " - " + eje.getMessage());
			((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		}
	}

	private String resolveToken(HttpServletRequest request){
		String bearerToken = request.getHeader("Authorization");
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7, bearerToken.length());
		}
		return null;
	}
}

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	private MyUserDetailsService userDetailsService;

	private final TokenProvider tokenProvider;

	SecurityConfiguration(MyUserDetailsService userDetailsService, TokenProvider tokenProvider){
		this.userDetailsService = userDetailsService;
		this.tokenProvider = tokenProvider;
	}

	/**
	 * This section defines the user accounts which can be used for
	 * authentication as well as the roles each user has.
	 */
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(username -> userDetailsService.loadUserByUsername(username));
	}

	/**
	 * This section defines the security policy for the app.
	 * - BASIC authentication is supported (enough for this REST-based demo)
	 * - /books, /authors. /accounts are secured using URL security shown below
	 * - CSRF headers are disabled since we are only testing the REST interface,
	 *   not a web one.
	 *
	 * NOTE: GET is not shown which defaults to permitted.
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http
				.httpBasic().and()
				.authorizeRequests()
				.antMatchers(HttpMethod.POST, "/account/login").permitAll()
				.antMatchers(HttpMethod.POST, "/books").hasRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/books/**").hasRole("ADMIN")
				.antMatchers(HttpMethod.PATCH, "/books/**").hasRole("ADMIN")
				.antMatchers(HttpMethod.POST, "/authors").hasRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/authors/**").hasRole("ADMIN")
				.antMatchers(HttpMethod.PATCH, "/authors/**").hasRole("ADMIN")
				.antMatchers(HttpMethod.PUT, "/accounts").hasRole("USER, ADMIN")
				.antMatchers(HttpMethod.PATCH, "/accounts").hasRole("USER, ADMIN")
				.antMatchers(HttpMethod.DELETE, "/accounts").hasRole("USER, ADMIN").and()
				.addFilterBefore(new JWTFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class) // JWT - Step 4
				.csrf().disable();
	}
}

@Entity
@Data
@NoArgsConstructor
@ToString(exclude = "password")
class Account {

	public static final PasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

	enum Role {ROLE_USER, ROLE_ADMIN}

	@Id
	@GeneratedValue
	private Long id;

	@Column(unique=true)
	@Size(min=1, max=255)
	private String userName;

	@JsonIgnore
	@Size(min=1, max=255)
	private String password;

	@ElementCollection(fetch = FetchType.EAGER)
	Set<Role> roles = new HashSet<>();

	Account(String userName, String password){
		this.userName = userName;
		this.password = PASSWORD_ENCODER.encode(password);
		roles.add(Role.ROLE_USER);
	}

	Account(String userName, String password, Set<Role> rs){
		this.userName = userName;
		this.password = PASSWORD_ENCODER.encode(password);
		roles.addAll(rs);
	}
}

@RepositoryRestResource
interface AccountRepository extends CrudRepository<Account, Long>{

	Optional<Account> findByUserName(@Param("userName") String userName);
}

@Component
class MyUserDetailsService implements UserDetailsService {

	private AccountRepository accountRepository;

	MyUserDetailsService(AccountRepository accountRepository){
		this.accountRepository = accountRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
		Optional<Account> accountOptional = this.accountRepository.findByUserName(name);
		if(!accountOptional.isPresent())
			throw new UsernameNotFoundException(name);

		Account account = accountOptional.get();
		return new User(account.getUserName(), account.getPassword(),
			AuthorityUtils.createAuthorityList(account.getRoles().stream().map(Account.Role::name).toArray(String[]::new)));
	}
}

@Data
@Entity
@NoArgsConstructor
class Book {

	@Id
	@GeneratedValue
	private Long id;

	@Size(min=1, max=255)
	private String title;

	@Size(min=1, max=255)
	private String description;

	@NotNull
	private LocalDate publishedDate;

	@NotNull
	@Embedded
	private Money price;

	@Size(min = 1)
	@ManyToMany
	private List<Author> authors;

	Book(String title, String description, LocalDate publishedDate, Money price, Author author) {
		this.title = title;
		this.description = description;
		this.publishedDate = publishedDate;
		this.price = price;
		this.authors = Arrays.asList(author);
	}

	Book(String title, String description, LocalDate publishedDate, Money price, List<Author> authors) {
		this.title = title;
		this.description = description;
		this.publishedDate = publishedDate;
		this.price = price;
		this.authors = authors;
	}
}

@Embeddable
@Data
@NoArgsConstructor
class Money {

	enum Currency {CAD, EUR, USD }

	@DecimalMin(value="0",inclusive=false)
	@Digits(integer=1000000000,fraction=2)
	private BigDecimal amount;

	private Currency currency;

	Money(BigDecimal amount){
		this(Currency.USD, amount);
	}

	Money(Currency currency, BigDecimal amount){
		this.currency = currency;
		this.amount = amount;
	}
}

@PreAuthorize("hasRole('USER')")
@RepositoryRestResource
interface  BookRepository extends CrudRepository<Book, Long> {

	@PreAuthorize("hasRole('ADMIN')")
	@Override
	Book save(Book book);

	@PreAuthorize("hasRole('ADMIN')")
	@Override
	void delete(Long aLong);

	List<Book> findByTitle(@Param("title") String title);
	List<Book> findByTitleContains(@Param("keyword") String keyword);
	List<Book> findByPublishedDateAfter(@Param("publishedDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate publishedDate);
	List<Book> findByTitleContainsAndPublishedDateAfter(@Param("keyword") String keyword,
														@Param("publishedDate") @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate publishedDate);
	List<Book> findByTitleContainsAndPriceCurrencyAndPriceAmountBetween(@Param("keyword") String keyword,
																		@Param("currency") Money.Currency currency,
																		@Param("low") BigDecimal low,
																		@Param("high") BigDecimal high);
	List<Book> findByAuthorsLastName(@Param("lastName") String lastName);
}

@Entity
@Data
@NoArgsConstructor
class Author {

	@Id
	@GeneratedValue
	private Long id;

	@Size(min = 1, max=255)
	private String firstName;

	@Size(min = 1, max = 255)
	private String lastName;

	@Size(min = 1)
	@ManyToMany(mappedBy = "authors")
	private List<Book> books;

	Author(String firstName, String lastName){
		this.firstName = firstName;
		this.lastName = lastName;
	}
}

@PreAuthorize("hasRole('USER')")
@RepositoryRestResource
interface AuthorRepository extends CrudRepository<Author, Long>{

	@PreAuthorize("hasRole('ADMIN')")
	@Override
	Author save(Author author);

	@PreAuthorize("hasRole('ADMIN')")
	@Override
	void delete(Long aLong);

	List<Author> findByLastName(@Param("lastName") String lastName);
	List<Author> findByBooksTitle(@Param("title") String title);
}

class SecurityUtils {

	/**
	 * Configures the Spring Security {@link SecurityContext} to be authenticated as the user with the given username and
	 * password as well as the given granted authorities.
	 *
	 * @param username must not be {@literal null} or empty.
	 * @param password must not be {@literal null} or empty.
	 * @param roles
	 */
	public static void runAs(String username, String password, String... roles) {

		Assert.notNull(username, "Username must not be null!");
		Assert.notNull(password, "Password must not be null!");

		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(username, password, AuthorityUtils.createAuthorityList(roles)));
	}
}