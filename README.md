# dns-cache-poisoning

Within the past few years, the Internet has faced increasing attacks to its system, leading to exploitation of its stability and accuracy. Due to increased spoofing attacks during the past decade, the accuracy and stability as well as security at organisational and individual levels of the internet system have been jeopardized. Since IP addresses form the basis of communication amongst servers within the internet, attackers usually try to trick the DNS by introducing a forced DNS entry consisting of fake IP addresses, mostly within the cache memory. These cache poisoning attacks exploit shortcomings within the DNS software in order to redirect client computers to an IP address different from that of the target website. Thus, cache poisoning attacks not only affect users serviced by the affected DNS server but also those serviced by its downstream servers. This technique is used to trick client computers into accepting malicious content from unauthorized servers as well as phishing attacks to extract confidential information such as credit card and bank details. The goal of this project is to build an “on-path”  DNS cache poisoner and identify the way to detect it. After detection we will implement mitigation strategies to solve DNS-cache poisoning. At last we will use mathematical models to evaluate the approaches using confusion matrix and Chi-square test.

To build an “on-path” DNS poisoner we will create a virtual machine on the same device on which we want to perform DNS poisoning. As both the machines will have the same network interface hence the on-path DNS attacker(i.e virtual machine) will be able to listen to each packet that is being out of it and it receives. The standard port for DNS query is 53 on client side so we will filter and look for packets being sent and received on Port 53. Once the “on-path” positioner reads the packet being sent to DNS Resolver, it will try to create an answer for the query with a malicious IP address and will send it to the receiver(using the exact same transaction ID of request and exactly same packet response). The client then will store this IP address in the cache and it will be poisoned. The main challenge for the DNS poisoner is to send the answer of the DNS query faster than the original resolver. We will explore both programming languages Python and Go in order to make it faster. As per our current study of various articles over the internet,  our initial hypothesis is that Python is much slower and hence it will be better to implement the DNS poisoning in GoLang. We will also try to optimize the program using suitable data-structures and algorithms in order to make it faster. The next task is to detect the DNS poisoning. As per our initial hypothesis, we are sure that if an attacker is trying to send the poisoned DNS-query answer then there will be two responses for each of the query being sent, one by the actual DNS resolver and another by the DNS attacker. The challenge in the above task is to avoid false positives results as due to DNS-based load balancing we can receive legitimate consecutive responses with different IP addresses for the same hostname. Once the task1 (i.e. The attacker is sending response faster than DNS Resolver) and task2 (i.e. the detection of DNS poisoning) is successfully implemented then we can move onto the next task of mitigating the DNS attack. We will look at the timeframe between the two responses of the same DNS query, as we have successfully implemented Task1 and Task2. As our response from the attacker is much faster than the DNS Resolver response, we can use the timeframe of response to identify the poisonous packet and then drop the first packet to mitigate it. We can experiment with TTL and time to frequently flush DNS cache to decrease the effect in case our DNS cache has been poisoned due to incorrectly dropping the legitimate response. But there is a tradeoff for this approach as regularly  flushing of the DNS cache can lead to more frequent requests to  DNS Resolver for a particular website which will be an overhead. Another implementation we will add in the mitigation strategy is  the technique of Echoing of the DNS response validation fields to avoid DNS poisoning. In this technique primarily, the response echo some unpredictable values sent with the request.


We will evaluate our mitigation technique on the basis of the confusion matrix. We will calculate the True Positives (i.e the packets which were poisoned and mitigated), True Negatives (i.e the packets which were not  poisoned and cached), False Positives (i.e the packets which were not  poisoned but mitigated) and False Negatives (i.e the packets which were not  poisoned but mitigated)  and we will calculate the accuracy, precision and recall on the basis of that information. At last we will implement a Chi-square on the given data to differentiate between observed frequencies and expected frequencies.

References
https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8550085
https://en.wikipedia.org/wiki/DNS_spoofing

