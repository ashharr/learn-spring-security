package com.springboot.learnspringsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldResource2 {

	@GetMapping("/hello-world")
	public String sayHelloWorld() {
		return "Hello World v1";
	}
}
