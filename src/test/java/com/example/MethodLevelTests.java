package com.example;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit4.SpringRunner;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.Arrays;

//import static org.springframework.test.web.servlet.htmlunit.MockMvcWebClientBuilder.webAppContextSetup;

import static org.junit.Assert.*;

/**
 * Created by Vernon on 2/23/2017.
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class MethodLevelTests {

    @Autowired
    BookRepository bookRepository;

    @Autowired
    AuthorRepository authorRepository;

    @Before
    public void setUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void rejectsMethodInvocationsForNoAuth() {

        try {
            bookRepository.findAll();
            fail("Expected a security error");
        } catch (AuthenticationCredentialsNotFoundException e) {
            // expected
        }

        try {
            bookRepository.save(new Book("MacBook Pro", "...", LocalDate.of(2016, 06, 28), new Money(new BigDecimal(45.83)),
                    Arrays.asList(authorRepository.save(new Author("Blow", "Smith")))));
            fail("Expected a security error");
        } catch (AuthenticationCredentialsNotFoundException e) {
            // expected
        }

        try {
            bookRepository.save(new Book("MacBook Pro", "...", LocalDate.of(2016, 06, 28), new Money(new BigDecimal(45.83)),
                    Arrays.asList(authorRepository.save(new Author("Blow", "Smith")))));
            fail("Expected a security error");
        } catch (AuthenticationCredentialsNotFoundException e) {
            // expected
        }
    }

    @Test
    public void rejectsMethodInvocationsForAuthWithInsufficientPermissions() {

        SecurityUtils.runAs("system", "system", "ROLE_USER");

        bookRepository.findAll();

        try {
            bookRepository.save(new Book("MacBook Pro", "...", LocalDate.of(2016, 06, 28), new Money(new BigDecimal(45.83)),
                    Arrays.asList(authorRepository.save(new Author("Blow", "Smith")))));
            fail("Expected a security error");
        } catch (AccessDeniedException e) {
            // expected
        }
        try {
            bookRepository.delete(1L);
            fail("Expected a security error");
        } catch (AccessDeniedException e) {
            // expected
        }
    }

    @Test
    public void allowsMethodInvocationsForAuthWithSufficientPermissions() {

        SecurityUtils.runAs("system", "system", "ROLE_USER", "ROLE_ADMIN");

        bookRepository.findAll();
        bookRepository.save(new Book("MacBook Pro", "...", LocalDate.of(2016, 06, 28), new Money(new BigDecimal(45.83)),
                Arrays.asList(authorRepository.save(new Author("Blow", "Smith")))));
        bookRepository.delete(1L);
    }
}
