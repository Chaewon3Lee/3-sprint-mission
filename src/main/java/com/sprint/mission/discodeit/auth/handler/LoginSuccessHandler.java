package com.sprint.mission.discodeit.auth.handler;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.sprint.mission.discodeit.auth.service.DiscodeitUserDetails;
import com.sprint.mission.discodeit.dto.response.UserResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication) throws IOException {

        System.out.println("[LoginSuccessHandler] 로그인 성공 처리 시작");

        if (authentication.getPrincipal() instanceof DiscodeitUserDetails userDetails) {
            UserResponse userResponse = userDetails.getUserResponse();

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.setStatus(HttpServletResponse.SC_OK);

            String jsonResponse = objectMapper.writeValueAsString(userResponse);
            response.getWriter().write(jsonResponse);

            System.out.println("[LoginSuccessHandler] 로그인 성공 응답 완료: " + userResponse.username());
        } else {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\": \"인증 정보를 처리할 수 없습니다.\"}");
        }
    }
}
