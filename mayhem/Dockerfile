FROM fuzzers/atheris:2.0.7-python3.9

RUN mkdir -p /markupsafe/mayhem
RUN mkdir -p /markupsafe/src
COPY ./src markupsafe/src
COPY ./mayhem markupsafe/mayhem

RUN chmod +x /markupsafe/mayhem/musafe_fuzzer.py
RUN chmod +x /markupsafe/mayhem/escape_fuzzer.sh
RUN chmod +x /markupsafe/mayhem/unescape_fuzzer.sh

ENV PYTHONPATH $PYTHONPATH:/markupsafe/src

