The lab dataset: two captures, read together by 01_window.py.

cic_ddos2019_sample.pcap.gz
    The CIC-DDoS2019 sample that the LUCID authors publish with their code
    (https://github.com/doriguzzi/lucid-ddos, folder sample-dataset, Apache-2.0, see
    LICENSE-lucid-ddos.txt): the traces
    CIC-DDoS-2019-Benign, -DNS, -SynFlood, -UDPLag and -WebDDoS, merged in time order.
    Attacker 172.16.0.5 (the router that hides the attack sources in the CIC testbed), victims
    192.168.50.1 and 192.168.50.4.
    Dataset: I. Sharafaldin, A. H. Lashkari, S. Hakak and A. A. Ghorbani, "Developing Realistic
    Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy," 53rd International Carnahan
    Conference on Security Technology (ICCST), 2019. https://www.unb.ca/cic/datasets/ddos-2019.html

lab_traffic.pcap.gz
    Recorded for this lab on the lab network (tools/record_lab_sessions.sh, tools/build_lab_dataset.sh):
    a web server 172.30.0.10, 17 benign users 172.30.0.20-36, attacker 172.30.0.66 (SYN flood and
    HTTP flood). The post-lab replays the validation flows of this network.
