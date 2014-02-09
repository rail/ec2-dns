import sys
import re

from twisted.names import dns, server, client, cache
from twisted.application import service, internet
from twisted.internet import defer
from twisted.python import log
from twisted.python.log import ILogObserver, FileLogObserver
from twisted.python.logfile import DailyLogFile

from boto.ec2 import connect_to_region

_conn = {}
regions = ["us-east-1", "us-west-2"]
id_regexp = re.compile(r"^i-[a-z0-9]{8}$")


def get_connection(region):
    if _conn.get(region):
        return _conn[region]
    # TODO: use secrets
    _conn[region] = connect_to_region(region)
    return _conn[region]


def query(name, region):
    conn = get_connection(region)
    res = None

    if id_regexp.match(name):
        # Lookup by instance ID
        res = conn.get_all_instances(instance_ids=[name])
    else:
        filters = {}
        if name.startswith("tag:"):
            # Lookup by multiple tags
            # tag:moz-loaned-to=j*,moz-type=tst*
            for pair in name[4:].split(","):
                tag, value = pair.split("=")
                filters["tag:%s" % tag] = value
        else:
            # Fallback to the FQDN tag
            filters = {"tag:FQDN": "%s" % name}
        res = conn.get_all_instances(filters=filters)
    if not res:
        return []
    ret = []
    for r in res:
        for i in r.instances:
            if i.private_ip_address:
                ret.append([i.tags.get("FQDN"), i.private_ip_address])
    return ret


def queryAddress(name):
    ret = []
    for r in regions:
        for fqdn, ip in query(name, r):
            ret.append(dns.RRHeader(auth=True, name=fqdn, ttl=600,
                                    payload=dns.Record_A(ip, 600)))
    if ret:
        return (ret, (), ())
    else:
        raise Exception("%s: not found" % name)


class DNSResolver(client.Resolver):
    def __init__(self):
        # pass /etc/hosts, since it's required
        client.Resolver.__init__(self, resolv="/etc/hosts")

    def lookupAddress(self, name, timeout=None):
        """
        The twisted function which is called when an A record lookup is
        requested.
        :param name: The domain name being queried for (e.g. example.org).
        :param timeout: Time in seconds to wait for the query response.
        (optional, default: None)
        :return: A DNS response for the record query.
        """
        log.msg("Query for %s" % name)
        d = defer.execute(queryAddress, name)
        return d


application = service.Application('EC2 DNS')
logfile = DailyLogFile("dns.log", ".")
application.setComponent(ILogObserver, FileLogObserver(logfile).emit)

dns_resolver = DNSResolver()

f = server.DNSServerFactory(caches=[cache.CacheResolver()],
                            clients=[dns_resolver])
p = dns.DNSDatagramProtocol(f)
f.noisy = p.noisy = False

ret = service.MultiService()
PORT = 1253

for (klass, arg) in [(internet.TCPServer, f), (internet.UDPServer, p)]:
    s = klass(PORT, arg)
    s.setServiceParent(ret)

ret.setServiceParent(service.IServiceCollection(application))

if __name__ == '__main__':
    print "Usage: sudo twistd -y %s (background) OR sudo twistd -noy %s " \
        "(foreground)" % (sys.argv[0], sys.argv[0])
