FROM golang
COPY bin/ssso /bin/ssso
RUN chmod u+x /bin/ssso
ENTRYPOINT [ "ssso" ]