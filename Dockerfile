FROM kong/kong:3.9-rhel
USER root
RUN yum install -y openssl-devel
USER kong
