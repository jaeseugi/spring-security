package security.demo.auth;

/**
 * packageName :  security.demo.auth
 * fileName : PrincipalDetails
 * author :  wotjr210
 * date : 2022/10/06
 * description :
 * ===========================================================
 * DATE                 AUTHOR                NOTE
 * -----------------------------------------------------------
 * 2022/10/06                wotjr210             최초 생성
 */

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import security.demo.model.User;

import java.util.ArrayList;
import java.util.Collection;

/**
 * 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
 * 로그인을 진행이 완료가 되면 시큐리티 session을 만들어 줍니다. ( 세션키 → Security ContextHodler)
 * 세션에 들어가는 오브젝트 타입 → Authentication 타입 객체
 * Authentication 안에 User 정보가 있어야됨.
 * User 오브젝트의 타입 → UserDetails 타입 객
 *
 * Security Session → Authentication → UserDetails
 * 시큐리티 세션에서 세션 정보를 꺼내면 Authentication 타입의 오브젝트를 반환하고 그 안에서 UserDetails(PrincipalDetails)를 꺼내면
 * User 오브젝트에 접근할 수 있다.
 *
 */
public class PrincipalDetails implements UserDetails {

    private User user; // 콤포지션

    public PrincipalDetails(User user) {
        this.user = user;
    }

    // 해당 유저의 권한을 리턴하는곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<GrantedAuthority>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });

        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        // 1년동안 회원이 로그인을 안하면 휴면 계정으로 하기로 함
        // 현재시간 - 로그인 시간 → 1년 초과하면 return false;
        return true;
    }
}
