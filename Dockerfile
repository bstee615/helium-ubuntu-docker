FROM ubuntu:21.04
# Install packages needed for clang and building
RUN apt update
RUN DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true apt install -yq clang-9 libclang-9-dev \
    cmake build-essential 

COPY helium /root/helium

# Build Helium
RUN cd /root/helium && mkdir build && cd build && cmake .. && make
# Install clang and Helium to convenient locations
RUN ln -s `which clang-9` /usr/local/bin/clang && ln -s ./lib/libhelium.so /usr/local/lib