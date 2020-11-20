FROM python:3.7

WORKDIR /usr/src/app
COPY . .

RUN pip install bandit coveralls && \
    pip install . && \
    pip install -r requirements-test.txt && \
    python setup.py develop && \
    apt update -y && \
    apt install vim -y && \
    rm -rf /usr/src/app/ # delete the code from the container at build time then mount it at run time using -volume flag.
    #repokid config config.json # Generate example config

EXPOSE 5000

ENTRYPOINT ["bash"]



# docker build . -tag repokid:latest

# docker run --rm --name repokid -it --network aardvark_default --volume /home/ec2-user/repokid/repokid:/usr/local/lib/python3.7/site-packages/repokid  repokid:1.0 bash
# docker exec -it repokid


main running somewhere
namespace

python auto reload module.
