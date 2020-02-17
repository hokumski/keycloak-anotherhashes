package com.keenetic.account.keycloak.anotherhashes;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class MD5PasswordHashProviderTest {

  @Test
  public void encode() {

    MD5PasswordHashProvider mdd = new MD5PasswordHashProvider("md5");
    assertEquals("df5ea29924d39c3be8785734f13169c6", mdd.encode("blabla", 0));
    assertEquals("0dd7cb886ee8bbe82a9ea7ab2dc37efa", mdd.encode("asadd", 0));

  }
}
