#!/bin/bash

set -ex

docker run -it --rm --name keycloak-anotherhashes -v "$(pwd)":/usr/src/mymaven -w /usr/src/mymaven maven:3.3-jdk-8 mvn clean package
echo "cp target/keycloak-anotherhashes-1.2.jar [your]/keycloak/deployments/"
#echo "cp target/keycloak-anotherhashes-1.2.jar ../../../dxp-services/keycloak/deployments/"
