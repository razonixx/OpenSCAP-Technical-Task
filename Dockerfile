FROM oraclelinux:7

RUN yum update -y
RUN yum install python3 openscap-utils scap-security-guide -y
RUN pip3 install lxml
RUN pip3 install beautifulsoup4

RUN mkdir -p /root/openscap/results
RUN mkdir /root/scans

ADD test_scan_2020-11-10T18-37-21.json /root/scans
ADD test_scan_2020-11-10T18-38-55.json /root/scans
ADD my_oscap.py /root/

CMD ["/bin/bash"]