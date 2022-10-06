package security.demo.config;

// 사용하지않는 import 정리 : 컨트롤 + 옵션 + o
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * packageName :  security.demo.config
 * fileName : SecurityConfig
 * author :  wotjr210
 * date : 2022/10/06
 * description :
 * ===========================================================
 * DATE                 AUTHOR                NOTE
 * -----------------------------------------------------------
 * 2022/10/06                wotjr210             최초 생성
 */

@Configuration
//@EnableWebSecurity
public class SecurityConfig {

    // https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                // /user/**의 경로로 접속시 인증이 필요함. 접근하면 403, Forbidden
                .antMatchers("/user/**").authenticated()
                // /manager/**의 경로로 접속시 인증과 권한(ROLE_ADMIN, ROLE_MANAGER)이 필요하다.
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                // /manager/**의 경로로 접속시 인증과 권한(ROLE_ADMIN)이 필요하다.
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                // 그외의 UrlPattern들에 대해서는 허용
                .anyRequest().permitAll()
                // 권한이 없을때 로그인 페이지로 이동
                .and()
                .formLogin()
                .loginPage("/login");


        return http.build();
    }
}
