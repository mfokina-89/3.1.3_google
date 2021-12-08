package web.security;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ScopeBuilder;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserDetailsService userDetailsService;
    private final SuccessUserHandler successUserHandler;

    public SecurityConfig(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService, SuccessUserHandler successUserHandler) {
        this.userDetailsService = userDetailsService;
        this.successUserHandler = successUserHandler;
    }

    @Autowired
    public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder()); // конфигурация для прохождения аутентификации
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers( "/login**", "/logout").permitAll()
                .antMatchers("/admin/**").access("hasRole('ADMIN')")
                .antMatchers("/user/**").access("hasAnyRole('ADMIN', 'USER')")
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter("email")
                .passwordParameter("password")
                .successHandler(successUserHandler)
                .and().logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .and()
                .csrf().disable();

    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public OAuth20Service oAuth20Service() {
        return new ServiceBuilder("235415510825-rrpnbt7ff8lmejphg35pp14l7290cgir.apps.googleusercontent.com")
                .apiSecret("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")
                .defaultScope(new ScopeBuilder().withScopes("profile","email"))
                .callback("http://localhost:8083/auth")
                .build(GoogleApi20.instance());
    }

}