FROM python:2.7-onbuild

RUN pip install bandit coveralls && \
    pip install . && \
    pip install -r test-requirements.txt && \
    python setup.py develop && \
    repokid config config.json # Generate example config

ENTRYPOINT ["repokid"]
