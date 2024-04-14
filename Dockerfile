FROM debian:12

RUN apt-get --yes update && apt-get --yes install less vim gdb gcc make python3 libreadline-dev
