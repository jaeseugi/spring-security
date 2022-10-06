package security.demo.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import security.demo.model.User;
import security.demo.repository.UserRepository;

/**
 * packageName :  security.demo.auth
 * fileName : PrincipalDetailsService
 * author :  wotjr210
 * date : 2022/10/06
 * description :
 * ===========================================================
 * DATE                 AUTHOR                NOTE
 * -----------------------------------------------------------
 * 2022/10/06                wotjr210             최초 생성
 */

/**
 * 시큐리티 설정에서 loginProcessingUrl("/login");
 * /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수가 실행됨.(규칙)
 */
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * loadUserByUsername의 파라미터 username을 사용하기 위해 form에서 넘어오는 input을 username로 해줘야한다.
     * 안그러면 시큐리티 필터 체인에서 .usernameParameter("username2") 선언해줘야 매핑이된다.
     *
     * 리턴하게 되면, 시큐리티 세션(내부 Authentication(내부 UserDetails))
     *
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("username = " + username);
        User findUser = userRepository.findByUsername(username);
        System.out.println("findUser = " + findUser);
        if (findUser != null) {
            return new PrincipalDetails(findUser);
        }
        return null;
    }
}
