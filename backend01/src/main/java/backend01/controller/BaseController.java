package backend01.controller;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BaseController {

	@RequestMapping("hello")
	public String hello() {
		return "hello on " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
	}

}
