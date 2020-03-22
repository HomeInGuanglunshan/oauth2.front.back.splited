package backend01.config;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.alibaba.fastjson.JSONObject;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("backend01").password(new BCryptPasswordEncoder().encode("backend01"))
				.roles("BACKEND01", "ADMIN", "USER").build());
		return manager;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.formLogin().and().authorizeRequests().anyRequest().authenticated().and()
				// by default uses a Bean by the name of corsConfigurationSource
				// 貌似不太行。refer to: https://blog.csdn.net/oblily/article/details/87880904
				.cors().and() // 没有这句，跨域login失败
				.csrf().disable();
		http.exceptionHandling().authenticationEntryPoint((request, response, exceptioin) -> {
			response.setContentType("application/json;charset=utf-8");

			Map<String, Object> map = new HashMap<>();
			map.put("status", 401);
			map.put("message", "please login");

			PrintWriter writer = response.getWriter();
			writer.write(JSONObject.toJSONString(map));
			writer.flush();
			writer.close();
		});
		http.formLogin().successHandler((request, response, authentication) -> {
			response.setContentType("application/json;charset=utf-8");

			Map<String, Object> map = new HashMap<>();
			map.put("status", 200);
			map.put("message", "login successfully");

			PrintWriter writer = response.getWriter();
			writer.write(JSONObject.toJSONString(map));
			writer.flush();
			writer.close();
		});
//		http.logout().clearAuthentication(true).invalidateHttpSession(true).deleteCookies(COOKIE_NAME);
		http.logout().logoutSuccessHandler((request, response, authentication) -> {
			response.setContentType("application/json;charset=utf-8");

			Map<String, Object> map = new HashMap<>();
			map.put("status", 200);
			map.put("message", "logout successfully");

			PrintWriter writer = response.getWriter();
			writer.write(JSONObject.toJSONString(map));
			writer.flush();
			writer.close();
		});
	}

	/**
	 * refer to: https://blog.csdn.net/oblily/article/details/87880904
	 *
	 * @return
	 */
	@Bean
	public CorsFilter corsFilter() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.addAllowedOrigin("*");
		configuration.setAllowCredentials(true);
		configuration.addAllowedHeader("*");
		configuration.addAllowedMethod("*");

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);

		CorsFilter corsFilter = new CorsFilter(source);

		// 这句貌似多余
//		FilterRegistrationBean<CorsFilter> registrationBean = new FilterRegistrationBean<>(corsFilter);
//		registrationBean.setOrder(0);

		return corsFilter;
	}

}
