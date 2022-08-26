FROM ubuntu:focal

RUN apt-get -q update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 \
      python3-pip \
      libpcap0.8-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install remaining sanipcap deps with pip
COPY requirements.txt /
RUN pip3 install --no-cache-dir -r /requirements.txt && \
    rm /requirements.txt && rm -rf ~/.cache/pip

# Install app
COPY sanicap/sanicap.py /usr/local/bin/
RUN chmod +x /usr/local/bin/sanicap.py
ENTRYPOINT ["/usr/bin/python3", "/usr/local/bin/sanicap.py"]
