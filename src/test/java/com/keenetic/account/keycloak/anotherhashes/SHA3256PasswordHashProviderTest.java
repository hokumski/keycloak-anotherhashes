package com.keenetic.account.keycloak.anotherhashes;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class SHA3256PasswordHashProviderTest {

  @Test
  public void encode() {

    // update CREDENTIAL set
    // secret_data='{"value":"3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392", "salt": ""}',
    // credential_data='{"hashIterations":0, "algorithm":"sha3-256"}'
    // WHERE USER_ID = '.....'

    SHA3256PasswordHashProvider sha3 = new SHA3256PasswordHashProvider("sha3-256");
    assertEquals("3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392", sha3.encode("hello", 0));
    assertEquals("420baf620e3fcd9b3715b42b92506e9304d56e02d3a103499a3a292560cb66b2", sha3.encode("world", 0));
    assertEquals("644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938", sha3.encode("hello world", 0));

  }

}
