package dk.itst.oiosaml.idp.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                .ignoringAntMatchers("/saml/sso")
                .and()
                .authorizeRequests()
                .mvcMatchers("/saml/**").permitAll()
                .mvcMatchers("/webjars/**").permitAll()
                .anyRequest().denyAll();
    }
}
