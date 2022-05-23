package com.cards.auth.config;

import org.glassfish.jersey.logging.LoggingFeature;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import java.util.logging.Level;
import java.util.logging.Logger;

@Configuration
public class ApplicationConfig {
    @Bean
    public Client client() {
        return ClientBuilder
                .newBuilder()
                .register(new LoggingFeature(Logger.getLogger(this.getClass().getName()),
                        Level.INFO, LoggingFeature.Verbosity.PAYLOAD_ANY, null))
                .build();
    }

}
