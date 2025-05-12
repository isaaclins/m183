package ch.bbw.pr.tresorbackend.model;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * ConfigProperties
 * @author Peter Rutschmann
 */
@Component
public class ConfigProperties {

   @Value("${CROSS_ORIGIN}")
   private String crossOrigin;

   public String getOrigin() {
      return crossOrigin;
   }
}
