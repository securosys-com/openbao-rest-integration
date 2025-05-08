## DOCKERHUB DOCKERFILE ##
FROM debian:stable-slim
VOLUME ["/tmp", "/opt/app/" ]
ENV BAO_ADDR='http://0.0.0.0:8200'
ENV BAO_API_ADDR='http://0.0.0.0:8200'
ENV BAO_ADDRESS='http://0.0.0.0:8200'
ENV PATH="$PATH:/opt/app"
#RUN yum -y update && yum -y install git curl vim-common jq
#ARG DEPENDENCY=install
COPY bin /opt/app
RUN \
  apt-get -y update && \
  apt-get -y install ca-certificates && \
  apt-get clean
EXPOSE 8200
EXPOSE 8201

ENTRYPOINT ["./opt/app/bao","server", "-config=/etc/app/config/config.hcl"]
