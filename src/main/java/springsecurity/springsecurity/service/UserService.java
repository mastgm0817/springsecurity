package springsecurity.springsecurity.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import springsecurity.springsecurity.utils.JwtUtil;

@Service
public class UserService {

    @Value("${secret}")
    private String secretKey;

    // 만료시간 1시간 설정
    private Long expiredMs = 1000*60*60l;
    public String login(String userName, String password){
        return JwtUtil.createJwt(userName, secretKey, expiredMs);
    }
}
