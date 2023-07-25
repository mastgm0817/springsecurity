package springsecurity.springsecurity.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import springsecurity.springsecurity.service.UserService;
import org.springframework.http.HttpHeaders;
import springsecurity.springsecurity.utils.JwtUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;


@Slf4j // 로그 메소드 사용 (system out println 방식으로 로그안찍어도됨)
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
// OncePerRequestFilter는 http요청 1번에 1번의 필터를 수행
    private final UserService userService;
    private final String secretKey;
    // userName Token에서 꺼내기


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authentication = request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("authorization : {}", authentication);


        // 토큰 안보내면 블럭
        if(authentication == null || !authentication.startsWith("Bearer ")){
            log.info("authorization 을 잘못보냈습니다.");
            filterChain.doFilter(request, response);
            return ;
        }

        //토큰 꺼내기
        String token = authentication.split(" ")[1]; // [0] 번째는 Bearer 일거임
//        String token1 = authentication.split(" ")[0]; // [0] 번째는 Bearer 일거임
//        log.info(token1);
        // 토큰 만료여부(expired)
        if (JwtUtil.isExpired(token, secretKey)){
            log.error("토큰이 만료되었습니다.");
            filterChain.doFilter(request, response);
        }

        //Username 토큰에서 꺼내기
        String userName = JwtUtil.getUserName(token, secretKey);
        log.info("username {}", userName);


        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userName, null, List.of(new SimpleGrantedAuthority("Role")));
                // credentials를 null로 해도 되는 이유는, 토큰이 발급되었다는건 이미 사용자가 인증이 완료되었다는 의미라서 null로 설정해주면, 메모리에서 password는 지움
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication((authenticationToken));
                filterChain.doFilter(request, response);
    }
}
