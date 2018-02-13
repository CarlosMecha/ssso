FROM golang
COPY bin/ssso /bin/ssso
COPY *.html /www/
RUN chmod u+x /bin/ssso
ENTRYPOINT [ "ssso" ]