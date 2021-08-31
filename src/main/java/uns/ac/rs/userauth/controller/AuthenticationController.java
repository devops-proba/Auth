package uns.ac.rs.userauth.controller;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import uns.ac.rs.userauth.domain.User;
import uns.ac.rs.userauth.dto.UserRegistrationDTO;
import uns.ac.rs.userauth.security.JwtAuthenticationRequest;
import uns.ac.rs.userauth.security.TokenUtils;
import uns.ac.rs.userauth.service.CustomUserDetailsService;
import uns.ac.rs.userauth.util.InvalidDataException;

@RestController
public class AuthenticationController {

	@Autowired
	TokenUtils tokenUtils;
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public ResponseEntity<String> createAuthenticationToken(@RequestBody JwtAuthenticationRequest authenticationRequest,
			HttpServletResponse response) throws AuthenticationException, IOException {

		final Authentication authentication;
		try {
			this.userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
			authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
						authenticationRequest.getPassword()));
		}
		catch(UsernameNotFoundException e) {
			return new ResponseEntity<String>(e.getMessage(),HttpStatus.NOT_ACCEPTABLE);
		}
		catch(BadCredentialsException e) {
			return new ResponseEntity<String>("Wrong password",HttpStatus.NOT_ACCEPTABLE);
		}
		SecurityContextHolder.getContext().setAuthentication(authentication);

		User user = (User) authentication.getPrincipal();
		if(!user.isVerified()) {
			return new ResponseEntity<String>("Not verified! See your email for verification.",HttpStatus.NOT_ACCEPTABLE);
		}
		String jwt = tokenUtils.generateToken(user.getUsername(), user.getAuthorities().get(0).getUserType());
		return new ResponseEntity<String>(jwt, HttpStatus.OK);
	}
	
	@GetMapping( value = "/logout")
    public ResponseEntity<String> logoutUser() {
        	SecurityContextHolder.clearContext();

            return new ResponseEntity<>("You successfully logged out!", HttpStatus.OK);

    }
	
	@RequestMapping(value = "/registration", method = RequestMethod.POST)
	public ResponseEntity<?> register(@RequestBody UserRegistrationDTO user) {
		try {
			System.out.println(user);
			return new ResponseEntity<User>(userDetailsService.saveRegisteredUser(user), HttpStatus.CREATED);
		} catch (InvalidDataException e) {
			return new ResponseEntity<String>(e.getMessage(), HttpStatus.NOT_ACCEPTABLE);
		} catch ( MailException | UnsupportedEncodingException |  InterruptedException e ) {		
			System.out.println(e.getMessage());
			System.out.println(e.getLocalizedMessage());
			return new ResponseEntity<String>("Error while sending e-mail. Check to see if you entered it right!",HttpStatus.BAD_REQUEST);
		}
	}
	
	@RequestMapping(value = "/confirm/{token}", method = RequestMethod.POST)
	public ResponseEntity<?> confirmRegistration(@PathVariable String token) {		
		try {
			return new ResponseEntity<Boolean>(userDetailsService.confirmRegistration(token), HttpStatus.CREATED);
		}
		catch(InvalidDataException e) {
			return new ResponseEntity<String>(e.getMessage(), HttpStatus.NOT_ACCEPTABLE);
		}
	}
}
