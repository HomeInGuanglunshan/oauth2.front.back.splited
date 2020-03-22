package backend02.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BaseController {

	@RequestMapping("userInfo")
	public Object userInfo(Principal principal) {
		return principal;
	}

}
