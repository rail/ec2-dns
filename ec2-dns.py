import sys
import re

from twisted.names import dns, server, client, cache
from twisted.application import service, internet
from twisted.internet import defer
from twisted.python import log
from twisted.python.log import ILogObserver, FileLogObserver
from twisted.python.logfile import DailyLogFile
from repoze.lru import lru_cache

from boto.ec2 import connect_to_region

regions = ["us-east-1", "us-west-2"]
id_regexp = re.compile(r"^i-[a-z0-9]{8}$")


@lru_cache(10)
def get_connection(region):
    return connect_to_region(region)


@lru_cache(100)
def query(full_name, region):
    name = full_name.replace(".ec2", "")
    conn = get_connection(region)
    instances = None

    if id_regexp.match(name):
        # Lookup by instance ID
        try:
            instances = conn.get_only_instances(instance_ids=[name])
        except:
            pass
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
            filters = {"tag:Name": "%s" % name}
        instances = conn.get_only_instances(filters=filters)
    if not instances:
        return []
    ret = []
    for i in instances:
        if i.private_ip_address:
            ret.append([full_name, i.private_ip_address])
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
