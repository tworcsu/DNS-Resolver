import sys
import time
from dns import name, namedict, query, message, exception
from dns import rdatatype as rd

class Resolver:

    _STARS = "*"*80 + "\n"
    _DASHES = "-"*80 + "\n"

    def __init__(self):
        self.answer_cache = namedict.NameDict()
        self.referral_cache = namedict.NameDict()
        self.referral_cache[name.root] = {rd.NS: [name.from_text('a.root-servers.net.'),
                                                  name.from_text('b.root-servers.net.')]}
        self.referral_cache[name.from_text('a.root-servers.net.')] = {rd.A: ['198.41.0.4']}
        self.referral_cache[name.from_text('b.root-servers.net.')] = {rd.A: ['199.9.14.201']}
        self.latencies = [0.0]

    def execute_command(self, line):
        print("COMMAND:  " + line)
        tokens = line.split()
        if tokens[0] == "resolve":
            self.resolve(name.from_text(tokens[1]), rd.from_text(tokens[2]))
        elif tokens[0] == "print":
            self.print_cache()
        elif tokens[0] == "quit":
            print("Program terminated")
            self.exit_program()
        else:
            print("Unknown command: {}; Skipping it.".format(line))
        print(self._STARS)

    def exit_program(self):
        exit(0)

    def print_cache(self):
        print("Answer cache contents:\n")
        pretty(dict(self.answer_cache))
        print("Referral cache contents:\n")
        pretty(dict(self.referral_cache))

    def resolve(self, host, rr_type):
        if host in self.answer_cache and rr_type in self.answer_cache[host]:
            print("{}*** QUERY {} for RRType {}\n"
                  "*** Answer found in cache".format(self._DASHES, host.to_text(),
                                                     rd.to_text(rr_type)))
            answer = self.answer_cache[host][rr_type]
        else:
            deepest_match = self.referral_cache.get_deepest_match(host)
            print("*** NS records fetched from cache: {}".format(
                [i.to_text() for i in deepest_match[1][rd.NS]]))
            answer = self._resolve_domain(host, rr_type, deepest_match)
            if answer is not None:
                answer = answer.to_text()
                if host not in self.answer_cache:
                    self.answer_cache[host] = {}
                self.answer_cache[host][rr_type] = answer
            print("{}*** QUERY {} for RRType {}".format(self._DASHES, host.to_text(),
                                                        rd.to_text(rr_type)))
        print("*** FINAL RESPONSE found with latency {}\n".format(sum(self.latencies)))
        print("{}\n{}".format(answer, self._DASHES))
        self.latencies = [0.0]

    def _resolve_domain(self, host, rr_type, deepest_match):
        my_query = message.make_query(host, rr_type, want_dnssec=True)
        start = time.time()
        response = None
        for next_domain in deepest_match[1][rd.NS]:
            next_ip = self.referral_cache[next_domain][rd.A]
            print("*** Nameserver {} has ip addresses {}".format(next_domain.to_text(), next_ip))
            print("*** QUERY name server {} at {} for {} {}".format(
                next_domain.to_text(), next_ip[0], host.to_text(), rd.to_text(rr_type)))
            try:
                response = query.udp(my_query, next_ip[0], timeout=3)
                break
            except exception.Timeout:
                print("*** Query timed out\n"
                      "*** Error querying nameserver {}; "
                      "trying next nameserver".format(next_domain.to_text()))
        end = time.time()
        self.latencies.append(end - start)

        if response is None:
            print("SERVFAIL due to timeout")
            return response
        print("*** Response received with latency: {}".format(self.latencies[-1]))
        print(response.to_text() + "\n")
        answer = self._handle_response(response)

        if answer:
            return answer
        else:
            deepest_match = self.referral_cache.get_deepest_match(host)
            print("*** Start next iteration with domain {} nameservers {}".format(
                deepest_match[0].to_text(), [i.to_text() for i in deepest_match[1][rd.NS]]))
            return self._resolve_domain(host, rr_type, deepest_match)

    def _handle_response(self, response):
        if response.rcode() > 0:
            return response

        if response.answer:
            for rr_set in response.answer:
                if rr_set.rdtype == rd.CNAME:
                    response = self._cname_chase(rr_set)
                    break
            return response

        soa_found = False
        for rr_set in response.authority:
            if rr_set.name not in self.referral_cache:
                self.referral_cache[rr_set.name] = {}
            item_list = []
            for item in rr_set.items:
                if item.rdtype == rd.SOA:
                    soa_found = True
                elif item.rdtype == rd.NS:
                    item_list.append(item.target)
                else:
                    item_list.append(item.to_text())
            self.referral_cache[rr_set.name][rr_set.rdtype] = item_list
        if soa_found:
            return response

        for rr_set in response.additional:
            for item in rr_set.items:
                if rr_set.name not in self.referral_cache:
                    self.referral_cache[rr_set.name] = {}
                self.referral_cache[rr_set.name][rr_set.rdtype] = [item.address]
        return None

    def _cname_chase(self, rr_set):
        print("*** Chase CNAME")
        host = min(rr_set).target
        deepest_match = self.referral_cache.get_deepest_match(host)
        print("*** NS records fetched from cache: {}".format(
            [i.to_text() for i in deepest_match[1][rd.NS]]))
        answer = self._resolve_domain(host, rd.A, deepest_match)
        answer.answer.insert(0, rr_set)
        return answer

# Pretty printing for nested dicts (modified by me) originally from
# https://stackoverflow.com/questions/3229419/how-to-pretty-print-nested-dictionaries
def pretty(d, indent=0):
    for key, value in d.items():
        if isinstance(key, int):
            print('  ' * indent + rd.to_text(key) + " :")
        else:
            print('  ' * indent + str(key) + " :")
        if isinstance(value, dict):
            pretty(value, indent+1)
        elif isinstance(value, list):
            print('  ' * (indent+1) + str([str(i) for i in value]) + "\n")
        else:
            print('  ' * (indent+1) + value + "\n")

def main():
    resolver = Resolver()
    with open(sys.argv[1], 'r') as command_file:
        for line in command_file:
           resolver.execute_command(line)

if __name__ == '__main__':
    main()
