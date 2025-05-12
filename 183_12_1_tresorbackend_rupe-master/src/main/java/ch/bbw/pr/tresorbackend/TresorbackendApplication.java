package ch.bbw.pr.tresorbackend;

import ch.bbw.pr.tresorbackend.model.ConfigProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.CrossOrigin;

@SpringBootApplication
public class TresorbackendApplication {
   public static void main(String[] args) {
      SpringApplication.run(TresorbackendApplication.class, args);
   }
}
