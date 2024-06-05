FROM python:3.10-slim

RUN python3.10 -m pip install poetry
RUN apt update
RUN apt install python3-launchpadlib -y
RUN apt install -y software-properties-common
RUN add-apt-repository ppa:oisf/suricata-stable
RUN apt install -y libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libmagic-dev libjansson-dev libnss3-dev libgeoip-dev pkg-config python3 python3-yaml rustc cargo
RUN apt install wget libpcre2-dev -y
RUN wget https://www.openinfosecfoundation.org/download/suricata-7.0.5.tar.gz
RUN tar -xvzf suricata-7.0.5.tar.gz
WORKDIR /suricata-7.0.5
RUN ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
RUN make
COPY ./docker/dev/data/suricata-config/suricata.yaml  /etc/suricata/suricata.yaml
RUN apt install python3-yaml
RUN pip install pyyaml
RUN make install-full
RUN suricata --build-info
# create app folder
RUN mkdir -p /app/
RUN mkdir /app/suricata-config
WORKDIR /app