FROM quay.io/markus/rust-lang

RUN \
  apt-get install libexpat1-dev


ENTRYPOINT ["/bin/bash"]
