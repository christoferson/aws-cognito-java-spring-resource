package com.kb.demo.resource;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredResourceController {

    @GetMapping(path = "/api/hello")
    public String hello() {
        return String.format("Secured Resource! %s", System.currentTimeMillis());
    }

}
