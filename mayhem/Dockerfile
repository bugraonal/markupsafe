FROM gcr.io/oss-fuzz-base/base-builder-python

# Copy the repo
RUN mkdir -p /markupsafe/mayhem
RUN mkdir -p /markupsafe/src
COPY . /markupsafe/

WORKDIR /markupsafe

#RUN python3 -m venv .venv
RUN pip3 install .

RUN chmod +x /markupsafe/mayhem/escape_fuzzer.py
RUN chmod +x /markupsafe/mayhem/unescape_fuzzer.py

