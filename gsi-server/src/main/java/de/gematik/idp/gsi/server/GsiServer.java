package de.gematik.idp.gsi.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class GsiServer {

  public static void main(final String[] args) {

    SpringApplication.run(GsiServer.class, args);
  }
}
