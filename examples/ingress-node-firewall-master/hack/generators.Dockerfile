FROM fedora:35

ARG GOVERSION="1.17.9"

# Installs dependencies that are required to compile eBPF programs
RUN dnf install -y kernel-devel make llvm clang glibc-devel.i686 unzip
RUN dnf clean all

VOLUME ["/src"]

WORKDIR /

# Installs a fairly modern distribution of Go
RUN curl -qL https://go.dev/dl/go$GOVERSION.linux-amd64.tar.gz -o go.tar.gz
RUN tar -xzf go.tar.gz
RUN rm go.tar.gz

ENV GOROOT /go
RUN mkdir -p /gopath
ENV GOPATH /gopath

ENV PATH $GOROOT/bin:$GOPATH/bin:$PATH

WORKDIR /tmp
# Copies some pre-required Go dependencies to avoid downloading them on each build
COPY Makefile Makefile
RUN make prereqs

WORKDIR /src

ENTRYPOINT ["make", "generate"]
