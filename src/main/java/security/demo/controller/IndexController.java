package security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import security.demo.model.User;
import security.demo.repository.UserRepository;

/**
 * packageName :  security.demo.controller
 * fileName : IndexController
 * author :  wotjr210
 * date : 2022/10/06
 * description :
 * ===========================================================
 * DATE                 AUTHOR                NOTE
 * -----------------------------------------------------------
 * 2022/10/06                wotjr210             최초 생성
 */

@Controller
public class IndexController {

    @Autowired
    public UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping(path = {"","/"})
    public String index() {
        // 머스테치 기본폴더 src/main/resources/
        // 뷰 리졸버 설정 : templates(prefix), .mustache(suffix)
        return "index"; // src/main/resources/templates/index.mustache
    }

    @GetMapping("/user")
    @ResponseBody
    public String user() {
        return "user";
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }

    // 스프링 시큐리티가 해당 주소를 낚아 챈다. 설정을 통해 수정이 필요하다. - SecurityConfig 파일 생성 후 작동 안함.
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        System.out.println(user);
        user.setRole("ROLE_USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        System.out.println();
        System.out.println("Password is         : " + rawPassword);
        System.out.println("Encoded Password is : " + encPassword);
        user.setPassword(encPassword);

        userRepository.save(user); // 회원가입 잘됨. 비밀번호 : 1234 > 시큐리티로 로그인을 할 수 없음. 이유는 패스워드가 암호화가 안되어있기 때문..
        return "redirect:/loginForm";
    }

}
