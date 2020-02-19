package kr.gracelove.demospringsecurity.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AccountControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AccountService accountService;

    @Test
    void index_anonymous() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithAnonymousUser
    void index_anonymous2() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    void index_with_user() throws Exception {
        mockMvc.perform(get("/")
                .with(
                        user("grace").roles("USER")
                ))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "grace", roles = "USER")
    void index_with_user2() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithCommonUser
    void index_with_user3() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    void admin_with_user() throws Exception {
        mockMvc.perform(get("/admin")
                .with(
                        user("grace").roles("USER")
                ))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    void admin_with_admin() throws Exception {
        mockMvc.perform(get("/admin")
                .with(
                        user("grace").roles("ADMIN")
                ))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "grace", roles = "ADMIN")
    void admin_with_admin2() throws Exception {
        mockMvc.perform(get("/admin"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    void login() throws Exception {
        String username = "grace";
        String password = "123";
        Account user = createCommmonUser(username, password);
        mockMvc.perform(formLogin().user(username, password))
                .andDo(print())
                .andExpect(authenticated());

    }

    @Test
    void login_fail() throws Exception {
        String username = "grace";
        String password = "123";
        Account user = createCommmonUser(username, password);
        mockMvc.perform(formLogin().user(username, "wrongpassword"))
                .andDo(print())
                .andExpect(unauthenticated());

    }

    private Account createCommmonUser(String username, String password) {
        Account account = new Account();
        account.setUsername(username);
        account.setPassword(password);
        account.setRole("USER");

        return accountService.createNew(account);
    }
}