package security.demo.config;

// 사용하지않는 import 정리 : 컨트롤 + 옵션 + o
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // Secured 어노테이션 활성화, preAuthrorize와 postAuthorize 어노테이션 활성화
public class SecurityConfig {

    // 해당 메소스의 리턴되는 오브첵트를 IoC로 등록해준다.
    // BCrypt는 단방향 암호화 알고리즘
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    // https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable(); // https://youtu.be/cC1tI8cOOOk
        http.authorizeRequests()
                // /user/**의 경로로 접속시 인증이 필요함. 접근하면 403, Forbidden
                .antMatchers("/user/**").authenticated()
                // /manager/**의 경로로 접속시 인증과 권한(ROLE_ADMIN, ROLE_MANAGER)이 필요하다.
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                // /manager/**의 경로로 접속시 인증과 권한(ROLE_ADMIN)이 필요하다.
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                // 그외의 UrlPattern들에 대해서는 허용
                // 그외의 UrlPattern들에 대해서는 허용
                .anyRequest().permitAll()
                // 권한이 없을때 로그인 페이지로 이동
                .and()
                .formLogin()
                .loginPage("/loginForm")
                //.usernameParameter("username2")
                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행합니다. 즉, 컨트롤러에 /login 만들어 줄 필요 없게됨.
                .defaultSuccessUrl("/"); // 기본으로 /로 호출을 해주지만 특정 /user같은 경로를 통해서 로그인화면으로 로그인후 그 url로 리다이렉트 시칸다.


        return http.build();
    }
}
