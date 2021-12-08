package web.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import web.model.Role;
import web.model.User;
import web.service.RoleService;
import web.service.UserService;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ExecutionException;


@Controller
public class LoginController {

    private final UserService userService;
    private final RoleService roleService;
    private final OAuth20Service oAuth20Service;

    @Autowired
    public LoginController(UserService userService, RoleService roleService, OAuth20Service oAuth20Service) {
        this.userService = userService;
        this.roleService = roleService;
        this.oAuth20Service = oAuth20Service;
    }

    @GetMapping(value = "/login")
    public String login() {
        return "loginpage";
    }

    @GetMapping(value = "/login/google")
    public  String redirectGoogle() {

        return "redirect:"+oAuth20Service.getAuthorizationUrl();
    }

    @GetMapping(value = "/auth")
    public String getGoogleUser(Model model, @RequestParam(value = "code", required = false) String code) throws InterruptedException
            , ExecutionException, IOException {
        OAuth2AccessToken accessToken = oAuth20Service.getAccessToken(code);
        OAuthRequest request = new OAuthRequest(Verb.GET, "https://www.googleapis.com/oauth2/v3/userinfo");
        oAuth20Service.signRequest(accessToken, request);
        Response response = oAuth20Service.execute(request);

        ObjectMapper mapper = new ObjectMapper();
        TypeReference<HashMap<String,String>> typeRef = new TypeReference<HashMap<String, String>>() {};
        HashMap<String,String> responseMap = mapper.readValue(response.getBody(), typeRef);

        List<Role> roles = roleService.getAllRoles();
        UsernamePasswordAuthenticationToken usernamePassAuthToken = new UsernamePasswordAuthenticationToken(responseMap.get("email")
                ,responseMap.get("sub"), roles);
        SecurityContextHolder.getContext().setAuthentication(usernamePassAuthToken);

        StringBuilder stringRoles = new StringBuilder();
        for (Role role : roles
        ) {
            stringRoles.append(role.getName()).append(" ");
        }
        model.addAttribute("user", responseMap.get("email"));
        model.addAttribute("roles", stringRoles);
        return "adminpage";
    }


    @GetMapping(value = "/user")
    public String userInfo(@AuthenticationPrincipal User user, Model model) {
        model.addAttribute("user", user);
        model.addAttribute("roles", user.getRoles());
        return "userpage";
    }

    @GetMapping(value = "/admin")
    public String listUsers(@AuthenticationPrincipal User user, Model model) {
        model.addAttribute("user", user.getEmail());
        model.addAttribute("roles", user.getRoles());
        return "adminpage";
    }
}

