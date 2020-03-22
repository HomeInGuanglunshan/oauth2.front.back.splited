package backend02.config;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.alibaba.fastjson.JSONObject;

@EnableWebSecurity
@EnableOAuth2Client
//@AutoConfigureAfter(TokenServicesConfig.class)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("backend02").password(new BCryptPasswordEncoder().encode("backend02"))
				.roles("BACKEND02", "ADMIN", "USER").build());
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

		http.addFilterBefore(backend01Filter(), BasicAuthenticationFilter.class);
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

	@Autowired
	OAuth2ClientContext oAuth2ClientContext;

	@Autowired
	DefaultTokenServices defaultTokenServices;

	public Filter backend01Filter() {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(
				"/sso/login");

		OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(backend01(), oAuth2ClientContext);
		filter.setRestTemplate(restTemplate);

//		UserInfoTokenServices tokenServices = new UserInfoTokenServices(backend01Resource().getUserInfoUri(),
//				backend01Resource().getClientId());
//		tokenServices.setRestTemplate(restTemplate);
//		filter.setTokenServices(tokenServices);

		filter.setTokenServices(defaultTokenServices);

		filter.setAuthenticationSuccessHandler((request, response, authentication) -> {
			new DefaultRedirectStrategy().sendRedirect(request, response, "http://localhost:8282/");
		});

		return filter;
	}

	@Bean("backend01")
	@ConfigurationProperties("security.oauth2.client")
	public AuthorizationCodeResourceDetails backend01() {
		return new AuthorizationCodeResourceDetails();
	}

	@Bean("backend01Resource")
	@ConfigurationProperties("security.oauth2.resource")
	public ResourceServerProperties backend01Resource() {
		return new ResourceServerProperties();
	}

	@Bean
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

}
