# dns-cache-poisoning

Within the past few years, the Internet has faced increasing attacks to its system, leading to exploitation of its stability and accuracy. Due to increased spoofing attacks during the past decade, the accuracy and stability as well as security at organisational and individual levels of the internet system have been jeopardized. Since IP addresses form the basis of communication amongst servers within the internet, attackers usually try to trick the DNS by introducing a forced DNS entry consisting of fake IP addresses, mostly within the cache memory. These cache poisoning attacks exploit shortcomings within the DNS software in order to redirect client computers to an IP address different from that of the target website. Thus, cache poisoning attacks not only affect users serviced by the affected DNS server but also those serviced by its downstream servers. This technique is used to trick client computers into accepting malicious content from unauthorized servers as well as phishing attacks to extract confidential information such as credit card and bank details. The goal of this project is to build an “on-path”  DNS cache poisoner and identify the way to detect it. After detection we will implement mitigation strategies to solve DNS-cache poisoning. At last we will use mathematical models to evaluate the approaches using confusion matrix and Chi-square test.

Two Virtual machines to be installed Victim (Guest1) and attacker (Guest2)

-----------------------------
dnspoison.go is file for poisoning attack

Run the file on attacker using : sudo go run dnspoison.go

-----------------------------

detection.py is a file for detecting a possible DNS spoofing attack 


Run the file on attacker  using  : sudo python3 detection.py


-----------------------------

mitigation.py is a file for categorising IPs as Poisonous and Non-Poisonous IPs for a  possible DNS spoofing attack 


Run the file on attacker  using  : sudo python3 detect_poison2.py


-------------------------------

On Victim (Guest1) run the browser and add any of the IP address from:

{"www.imdb.com", "www.stonybrook.edu", "www.blackboard.com","www.whatsapp.com", "www.office.com","www.netflix.com","www.spotify.com","www.myshopify.com","www.wikipedia.org"}

as we have spoofed for this only


-------------------------------
References
https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8550085
https://en.wikipedia.org/wiki/DNS_spoofing

