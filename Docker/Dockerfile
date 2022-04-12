FROM ubuntu:18.04 as base

MAINTAINER Marcos Schejtman <marcos.schejtman@logrhythm.com>
LABEL build_date="02/04/2022"


SHELL ["/bin/bash", "-c"]  

RUN apt-get -y update
RUN apt-get -y install aptitude
RUN aptitude -y install curl wget git
RUN aptitude -y install python3-all python3  python3-pip	python3-virtualenv python-virtualenv  	libffi-dev unixodbc-dev vim
RUN useradd -m -s /bin/bash hunter
USER hunter
RUN cd /home/hunter && git clone https://github.com/natashell666/LRAutomationHuntingApp.git 
COPY ./requirements.txt /home/hunter/LRAutomationHuntingApp
USER hunter
RUN cd /home/hunter/ && virtualenv -p /usr/bin/python3 threat_hunting && source /home/hunter/threat_hunting/bin/activate &&  pip3 install -r LRAutomationHuntingApp/requirements.txt


ENTRYPOINT ["/bin/bash"]
