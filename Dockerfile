FROM kong/kong:3.5-rhel
USER root
RUN yum install -y openssl-devel
USER kong
