package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.hateoas.MediaTypes;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.Charset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.*;

@RunWith(SpringRunner.class)
@SpringBootTest
public class UrlLevelSecurityTests {

    static final MediaType APPLICATION_JSON_UTF8 = new MediaType("application", "hal+json", Charset.forName("utf8"));

    @Autowired
    AuthorRepository authorRepository;

    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private FilterChainProxy filterChain;

    private String userToken;

    private String adminToken;

    @Before
    public void setUp() throws Exception {
        this.mockMvc = webAppContextSetup(context).addFilters(filterChain).build();
        SecurityContextHolder.clearContext();

        String returnedContent = this.mockMvc.perform(post("/accounts/login")
                .contentType(APPLICATION_JSON_UTF8)
                .content(objectMapper.writeValueAsString(new LoginData("user", "user"))))
//                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString();
        userToken = objectMapper.readValue(returnedContent, String.class);

        returnedContent = this.mockMvc.perform(post("/accounts/login")
                .contentType(APPLICATION_JSON_UTF8)
                .content(objectMapper.writeValueAsString(new LoginData("admin", "admin"))))
//                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString();
        adminToken = objectMapper.readValue(returnedContent, String.class);

    }

    @Test
	public void shouldReturnTokenAfterLogin() throws Exception {

        String returnedContent = this.mockMvc.perform(post("/accounts/login")
				.contentType(APPLICATION_JSON_UTF8)
				.content(objectMapper.writeValueAsString(new LoginData("user", "user"))))
				.andExpect(status().isOk())
                .andDo(print())
                .andReturn()
                .getResponse()
                .getContentAsString();

       String returnedBody = objectMapper.readValue(returnedContent, String.class);
       String [] strArr = returnedBody.split("\\.");
       assertThat(strArr.length).isEqualTo(3);
	}

    @Test
    public void allowsAccessToRootResource() throws Exception {

        mockMvc.perform(get("/").//
                accept(MediaTypes.HAL_JSON)).//
                andExpect(content().contentTypeCompatibleWith(MediaTypes.HAL_JSON)).//
                andExpect(status().isOk()).//
                andDo(print());
    }

    @Test
    public void allowsAccessToResource() throws Exception {

        mockMvc.perform(get("/accounts").//
                accept(MediaTypes.HAL_JSON)).//
                andExpect(content().contentTypeCompatibleWith(MediaTypes.HAL_JSON)).//
                andExpect(status().isOk()).//
                andDo(print());
    }

    @Test
    public void rejectsPostAccessToCollectionResource() throws Exception {

        this.mockMvc
            .perform(post("/authors")
            .accept(MediaTypes.HAL_JSON)
            .contentType(APPLICATION_JSON_UTF8)
            .content(objectMapper.writeValueAsString(new Author("joe", "smith"))))
            .andExpect(status().isUnauthorized()).//
                andDo(print());
    }

    @Test
    public void allowsGetRequestsButRejectsPostForUser() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.ACCEPT, MediaTypes.HAL_JSON_VALUE);
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + userToken);

        mockMvc.perform(get("/books").//
                headers(headers).//.
                contentType(APPLICATION_JSON_UTF8)).
                andExpect(status().isOk()).//
                andDo(print());

        mockMvc.perform(post("/books").//
                headers(headers)).//
                andExpect(status().isForbidden()).//
                andDo(print());
    }

    @Test
    public void allowsPostRequestForAdmin() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, MediaTypes.HAL_JSON_VALUE);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken);

        mockMvc.perform(get("/authors").//
                headers(headers)).//
                andExpect(content().contentTypeCompatibleWith(MediaTypes.HAL_JSON)).//
                andExpect(status().isOk()).//
                andDo(print());

        Author author = new Author("Saruman", "White");

        String authorContent = mockMvc.perform(post("/authors").//
                headers(headers).//
                content(objectMapper.writeValueAsString(author))).
                andExpect(status().isCreated()).
                andDo(print()).
                andReturn().
                getResponse().
                getContentAsString();

        author  = objectMapper.readValue(authorContent, Author.class);
        assertThat(author.getFirstName()).isEqualTo("Saruman");
        assertThat(author.getLastName()).isEqualTo("White");
    }
}
