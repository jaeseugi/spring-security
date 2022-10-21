package security.demo.config;

// 사용하지않는 import 정리 : 컨트롤 + 옵션 + o

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import security.demo.auth.PrincipalDetails;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

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

@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// Secured 어노테이션 활성화, preAuthrorize와 postAuthorize 어노테이션 활성화
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
                .antMatchers("/user/**").authenticated() // /user/**의 경로로 접속시 인증 필요. 접근하면 403, Forbidden
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") // /manager/**의 경로로 접속시 인증과 권한(ROLE_ADMIN, ROLE_MANAGER) 필요
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')") // /manager/**의 경로로 접속시 인증과 권한(ROLE_ADMIN) 필요
                .anyRequest().permitAll() // 그외의 UrlPattern들에 대해서는 허용
                .and()
                .formLogin()
                .loginPage("/loginForm") // 사용자 정의 로그인 페이지 설정. default : /login
                //.usernameParameter("username2") // 아이디 파라미터명 설정. default : username
                //.passwordParameter("password2") // 패스워드 파라미터 설정. default : password
                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행합니다. 즉, 컨트롤러에 /login 만들어 줄 필요 없게됨.
                .defaultSuccessUrl("/") // 기본으로 /로 호출을 해주지만 특정 /user같은 경로를 통해서 로그인화면으로 로그인후 그 url로 리다이렉트 시칸다.
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.addCookie(new Cookie("AAA", "BBB"));

                        String credentials = String.valueOf(authentication.getCredentials());
                        System.out.println("User Password(Credentials) = " + credentials);
                        System.out.println("==================================");
                        List<GrantedAuthority> authorities = (List<GrantedAuthority>)authentication.getAuthorities();
                        authorities.stream().forEach( authoritiy -> {
                            System.out.println("권한 = " + authoritiy.getAuthority());
                        });
                        System.out.println("==================================");
                        boolean authenticated = authentication.isAuthenticated();
                        System.out.println("IsAuthenticated = " + authenticated);

                        UserDetails principal = (PrincipalDetails) authentication.getPrincipal();// UserDetails 객체 반환
                        System.out.println("UserDetails  Name = " + principal.getUsername());
                        System.out.println("UserDetails Password = " + principal.getPassword());

                        WebAuthenticationDetails webAuthenticationDetails = (WebAuthenticationDetails)authentication.getDetails(); // 직접적으로 사용자를 나타내는 정보가 아니라 인증 시에 부가적인 정보를 저장하는데 사용
                        System.out.println("IP : " + webAuthenticationDetails.getRemoteAddress());
                        System.out.println("Session ID : " + webAuthenticationDetails.getSessionId());
                    }
                }) // 로그인 성공 후 실행
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("SecurityConfig.onAuthenticationFailure");
                        exception.printStackTrace();
                        response.sendRedirect("/");
                    }
                }); // 로그인 실패 후 실행


        return http.build();
    }
}
