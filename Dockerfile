FROM ansi/mosquitto
MAINTAINER Alexandre Vasconcellos, alexv@cpqd.com.br

USER root
RUN apt-get update && apt-get install -y python-requests python-openssl python-flask curl

RUN  mkdir -p /var/www
COPY *.py  /var/www/

COPY mosquitto-files/access.acl /usr/local/src/mosquitto-1.4.13/certs/access.acl
COPY mosquitto-files/mosquitto.conf /usr/local/src/mosquitto-1.4.13/mosquitto.conf
COPY initialConf.py /usr/local/src/mosquitto-1.4.13/initialConf.py
COPY entrypoint.sh /usr/local/src/mosquitto-1.4.13/

RUN chown -R mosquitto /usr/local/src/mosquitto-1.4.13/ && \
	chmod +x /usr/local/src/mosquitto-1.4.13/entrypoint.sh  && \
	chmod +x /usr/local/src/mosquitto-1.4.13/initialConf.py && \
	ln /var/www/conf.py /usr/local/src/mosquitto-1.4.13/conf.py 

USER mosquitto
EXPOSE 8883

CMD ["/usr/local/src/mosquitto-1.4.13/entrypoint.sh"]
