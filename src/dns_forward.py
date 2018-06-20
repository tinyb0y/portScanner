from src.rfunctions import *
from src.custlogger import *
from collections import defaultdict

try:
  import dns.rdatatype
  import dns.message
  import dns.query
  import dns.reversename
except ImportError:
  notfound.append('dnspython')

logger = logging.getLogger(__name__)

def dns_query(server, timeout, protocol, qname, qtype, qclass):
  request = dns.message.make_query(qname, qtype, qclass)

  if protocol == 'tcp':
    response = dns.query.tcp(request, server, timeout=timeout, one_rr_per_rrset=True)

  else:
    response = dns.query.udp(request, server, timeout=timeout, one_rr_per_rrset=True)

    if response.flags & dns.flags.TC:
      response = dns.query.tcp(request, server, timeout=timeout, one_rr_per_rrset=True)

  return response

def generate_tld():
  # NB. does not return an exhaustive list (ie. missing co.uk, co.nz etc.)

  from itertools import product
  from string import ascii_lowercase

  # http://data.iana.org/TLD/tlds-alpha-by-domain.txt
  gtld = ['academy', 'actor', 'aero', 'agency', 'archi', 'arpa', 'asia', 'axa',
    'bar', 'bargains', 'berlin', 'best', 'bid', 'bike', 'biz', 'black', 'blue',
    'boutique', 'build', 'builders', 'buzz', 'cab', 'camera', 'camp', 'cards',
    'careers', 'cat', 'catering', 'center', 'ceo', 'cheap', 'christmas',
    'cleaning', 'clothing', 'club', 'codes', 'coffee', 'cologne', 'com',
    'community', 'company', 'computer', 'condos', 'construction', 'contractors',
    'cooking', 'cool', 'coop', 'country', 'cruises', 'dance', 'dating', 'democrat',
    'diamonds', 'directory', 'dnp', 'domains', 'edu', 'education', 'email',
    'enterprises', 'equipment', 'estate', 'events', 'expert', 'exposed', 'farm',
    'fish', 'fishing', 'flights', 'florist', 'foundation', 'futbol', 'gallery',
    'gift', 'glass', 'gov', 'graphics', 'guitars', 'guru', 'haus', 'holdings',
    'holiday', 'horse', 'house', 'immobilien', 'industries', 'info', 'ink',
    'institute', 'int', 'international', 'jetzt', 'jobs', 'kaufen', 'kim',
    'kitchen', 'kiwi', 'koeln', 'kred', 'land', 'lighting', 'limo', 'link',
    'london', 'luxury', 'maison', 'management', 'mango', 'marketing', 'meet',
    'menu', 'miami', 'mil', 'mobi', 'moda', 'moe', 'monash', 'museum', 'nagoya',
    'name', 'net', 'neustar', 'ninja', 'nyc', 'okinawa', 'onl', 'org', 'partners',
    'parts', 'photo', 'photography', 'photos', 'pics', 'pink', 'plumbing', 'post',
    'pro', 'productions', 'properties', 'pub', 'qpon', 'recipes', 'red', 'ren',
    'rentals', 'repair', 'report', 'reviews', 'rich', 'rodeo', 'ruhr', 'sexy',
    'shiksha', 'shoes', 'singles', 'social', 'sohu', 'solar', 'solutions',
    'supplies', 'supply', 'support', 'systems', 'tattoo', 'technology', 'tel',
    'tienda', 'tips', 'today', 'tokyo', 'tools', 'trade', 'training', 'travel',
    'uno', 'vacations', 'vegas', 'ventures', 'viajes', 'villas', 'vision', 'vodka',
    'vote', 'voting', 'voto', 'voyage', 'wang', 'watch', 'webcam', 'wed', 'wien',
    'wiki', 'works', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--45brj9c',
    'xn--55qw42g', 'xn--55qx5d', 'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80ao21a',
    'xn--80asehdb', 'xn--80aswg', 'xn--90a3ac', 'xn--c1avg', 'xn--cg4bki',
    'xn--clchc0ea0b2g2a9gcd', 'xn--czru2d', 'xn--d1acj3b', 'xn--fiq228c5hs',
    'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s', 'xn--fpcrj9c3d', 'xn--fzc2c9e2c',
    'xn--gecrj9c', 'xn--h2brj9c', 'xn--i1b6b1a6a2e', 'xn--io0a7i', 'xn--j1amh',
    'xn--j6w193g', 'xn--kprw13d', 'xn--kpry57d', 'xn--l1acc', 'xn--lgbbat1ad8j',
    'xn--mgb9awbf', 'xn--mgba3a4f16a', 'xn--mgbaam7a8h', 'xn--mgbab2bd',
    'xn--mgbayh7gpa', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgberp4a5d4ar',
    'xn--mgbx4cd0ab', 'xn--ngbc5azd', 'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--o3cw4h',
    'xn--ogbpf8fl', 'xn--p1ai', 'xn--pgbs0dh', 'xn--q9jyb4c', 'xn--rhqv96g',
    'xn--s9brj9c', 'xn--unup4y', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xkc2al3hye2a',
    'xn--xkc2dl3a5ee0h', 'xn--yfro4i67o', 'xn--ygbi2ammx', 'xn--zfr164b', 'xxx',
    'xyz', 'zone']

  cctld = [''.join(i) for i in product(*[ascii_lowercase]*2)]

  tld = gtld + cctld
  return tld, len(tld)

def generate_srv():
  common = [
    '_gc._tcp', '_kerberos._tcp', '_kerberos._udp', '_ldap._tcp',
    '_test._tcp', '_sips._tcp', '_sip._udp', '_sip._tcp', '_aix._tcp', '_aix._udp',
    '_finger._tcp', '_ftp._tcp', '_http._tcp', '_nntp._tcp', '_telnet._tcp',
    '_whois._tcp', '_h323cs._tcp', '_h323cs._udp', '_h323be._tcp', '_h323be._udp',
    '_h323ls._tcp', '_h323ls._udp', '_sipinternal._tcp', '_sipinternaltls._tcp',
    '_sip._tls', '_sipfederationtls._tcp', '_jabber._tcp', '_xmpp-server._tcp', '_xmpp-client._tcp',
    '_imap.tcp', '_certificates._tcp', '_crls._tcp', '_pgpkeys._tcp', '_pgprevokations._tcp',
    '_cmp._tcp', '_svcp._tcp', '_crl._tcp', '_ocsp._tcp', '_PKIXREP._tcp',
    '_smtp._tcp', '_hkp._tcp', '_hkps._tcp', '_jabber._udp', '_xmpp-server._udp',
    '_xmpp-client._udp', '_jabber-client._tcp', '_jabber-client._udp',
    '_adsp._domainkey', '_policy._domainkey', '_domainkey', '_ldap._tcp.dc._msdcs', '_ldap._udp.dc._msdcs']

  def distro():
    import os
    import re
    files = ['/usr/share/nmap/nmap-protocols', '/usr/share/nmap/nmap-services', '/etc/protocols', '/etc/services']
    ret = []
    for f in files:
      if not os.path.isfile(f):
        logger.warn("File '%s' is missing, there will be less records to test" % f)
        continue
      for line in open(f):
        match = re.match(r'([a-zA-Z0-9]+)\s', line)
        if not match: continue
        for w in re.split(r'[^a-z0-9]', match.group(1).strip().lower()):
          ret.extend(['_%s.%s' % (w, i) for i in ('_tcp', '_udp')])
    return ret

  srv = set(common + distro())
  return srv, len(srv)

class HostInfo:
  def __init__(self):
    self.name = set()
    self.ip = set()
    self.alias = set()

  def __str__(self):
    line = ''
    if self.name:
      line = ' '.join(self.name)
    if self.ip:
      if line: line += ' / '
      line += ' '.join(map(str, self.ip))
    if self.alias:
      if line: line += ' / '
      line += ' '.join(self.alias)

    return line

class Controller_DNS(Controller):
  records = defaultdict(list)
  hostmap = defaultdict(HostInfo)

  # show_final {{{
  def show_final(self):
    ''' Expected output:
    Records -----
          ftp.example.com.   IN A       10.0.1.1
          www.example.com.   IN A       10.0.1.1
         prod.example.com.   IN CNAME   www.example.com.
         ipv6.example.com.   IN AAAA    dead:beef::
          dev.example.com.   IN A       10.0.1.2
          svn.example.com.   IN A       10.0.2.1
      websrv1.example.com.   IN CNAME   prod.example.com.
         blog.example.com.   IN CNAME   example.wordpress.com.
    '''
    print('Records ' + '-'*42)
    for name, infos in sorted(self.records.items()):
      for qclass, qtype, rdata in infos:
        print('%34s %4s %-7s %s' % (name, qclass, qtype, rdata))

    ''' Expected output:
    Hostmap ------
           ipv6.example.com dead:beef::
            ftp.example.com 10.0.1.1
            www.example.com 10.0.1.1
           prod.example.com
        websrv1.example.com
            dev.example.com 10.0.1.2
            svn.example.com 10.0.2.1
      example.wordpress.com ?
           blog.example.com
    Domains ---------------------------
                example.com 8
    Networks --------------------------
                           dead:beef::
                              10.0.1.x
                              10.0.2.1
    '''
    ipmap = defaultdict(HostInfo)
    noips = defaultdict(list)

    '''
    hostmap = {
       'www.example.com': {'ip': ['10.0.1.1'], 'alias': ['prod.example.com']},
       'ftp.example.com': {'ip': ['10.0.1.1'], 'alias': []},
       'prod.example.com': {'ip': [], 'alias': ['websrv1.example.com']},
       'ipv6.example.com': {'ip': ['dead:beef::'], 'alias': []},
       'dev.example.com': {'ip': ['10.0.1.2'], 'alias': []},
       'example.wordpress.com': {'ip': [], 'alias': ['blog.example.com']},

    ipmap = {'10.0.1.1': {'name': ['www.example.com', 'ftp.example.com'], 'alias': ['prod.example.com', 'websrv1.example.com']}, ...
    noips = {'example.wordpress.com': ['blog.example.com'],
    '''

    for name, hinfo in self.hostmap.items():
      for ip in hinfo.ip:
        ip = IP(ip)
        ipmap[ip].name.add(name)
        ipmap[ip].alias.update(hinfo.alias)

    for name, hinfo in self.hostmap.items():
      if not hinfo.ip and hinfo.alias:
        found = False
        for ip, v in ipmap.items():
          if name in v.alias:
            for alias in hinfo.alias:
              ipmap[ip].alias.add(alias)
              found = True

        if not found: # orphan CNAME hostnames (with no IP address) may be still valid virtual hosts
          noips[name].extend(hinfo.alias)

    print('Hostmap ' + '-'*42)
    for ip, hinfo in sorted(ipmap.items()):
      for name in hinfo.name:
        print('%34s %s' % (name, ip))
      for alias in hinfo.alias:
        print('%34s' % alias)

    for k, v in noips.items():
      print('%34s ?' % k)
      for alias in v:
        print('%34s' % alias)

    print('Domains ' + '-'*42)
    domains = {}
    for ip, hinfo in ipmap.items():
      for name in hinfo.name.union(hinfo.alias):
        if name.count('.') > 1:
          i = 1
        else:
          i = 0
        d = '.'.join(name.split('.')[i:])
        if d not in domains: domains[d] = 0
        domains[d] += 1

    for domain, count in sorted(domains.items(), key=lambda a:a[0].split('.')[-1::-1]):
      print('%34s %d' % (domain, count))

    print('Networks ' + '-'*41)
    nets = {}
    for ip in set(ipmap):
      if not ip.version() == 4:
        nets[ip] = [ip]
      else:
        n = ip.make_net('255.255.255.0')
        if n not in nets: nets[n] = []
        nets[n].append(ip)

    for net, ips in sorted(nets.items()):
      if len(ips) == 1:
        print(' '*34 + ' %s' % ips[0])
      else:
        print(' '*34 + ' %s.x' % '.'.join(str(net).split('.')[:-1]))

  # }}}

  def push_final(self, resp):
    if hasattr(resp, 'rrs'):
      for rr in resp.rrs:
        name, qclass, qtype, data = rr

        info = (qclass, qtype, data)
        if info not in self.records[name]:
          self.records[name].append(info)

        if not qclass == 'IN':
          continue

        if qtype == 'PTR':
          data = data[:-1]
          self.hostmap[data].ip.add(name)

        else:
          if qtype in ('A', 'AAAA'):
            name = name[:-1]
            self.hostmap[name].ip.add(data)

          elif qtype == 'CNAME':
            name, data = name[:-1], data[:-1]
            self.hostmap[data].alias.add(name)

class DNS_reverse:
  '''Reverse DNS lookup'''

  usage_hints = [
    '''%prog host=NET0 0=192.168.0.0/24 -x ignore:code=3''',
    '''%prog host=NET0 0=216.239.32.0-216.239.47.255,8.8.8.0/24 -x ignore:code=3 -x ignore:fgrep!=google.com -x ignore:fgrep=216-239-''',
    ]

  available_options = (
    ('host', 'IP addresses to reverse lookup'),
    ('server', 'name server to query (directly asking a zone authoritative NS may return more results) [8.8.8.8]'),
    ('timeout', 'seconds to wait for a response [5]'),
    ('protocol', 'send queries over udp or tcp [udp]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, server='8.8.8.8', timeout='5', protocol='udp'):

    with Timing() as timing:
      response = dns_query(server, int(timeout), protocol, dns.reversename.from_address(host), qtype='PTR', qclass='IN')

    code = response.rcode()
    status = dns.rcode.to_text(code)
    rrs = [[host, c, t, d] for _, _, c, t, d in [rr.to_text().split(' ', 4) for rr in response.answer]]

    mesg = '%s %s' % (status, ''.join('[%s]' % ' '.join(rr) for rr in rrs))
    resp = self.Response(code, mesg, timing)

    resp.rrs = rrs

    return resp

class DNS_forward:
  '''Forward DNS lookup'''

  usage_hints = [
    '''%prog name=FILE0.google.com 0=names.txt -x ignore:code=3''',
    '''%prog name=google.MOD0 0=TLD -x ignore:code=3''',
    '''%prog name=MOD0.microsoft.com 0=SRV qtype=SRV -x ignore:code=3''',
    ]

  available_options = (
    ('name', 'domain names to lookup'),
    ('server', 'name server to query (directly asking the zone authoritative NS may return more results) [8.8.8.8]'),
    ('timeout', 'seconds to wait for a response [5]'),
    ('protocol', 'send queries over udp or tcp [udp]'),
    ('qtype', 'type to query [ANY]'),
    ('qclass', 'class to query [IN]'),
    )
  available_actions = ()

  available_keys = {
    'TLD': generate_tld,
    'SRV': generate_srv,
    }

  Response = Response_Base

  def execute(self, name, server='8.8.8.8', timeout='5', protocol='udp', qtype='ANY', qclass='IN'):

    with Timing() as timing:
      response = dns_query(server, int(timeout), protocol, name, qtype=qtype, qclass=qclass)

    code = response.rcode()
    status = dns.rcode.to_text(code)
    rrs = [[n, c, t, d] for n, _, c, t, d in [rr.to_text().split(' ', 4) for rr in response.answer + response.additional + response.authority]]

    mesg = '%s %s' % (status, ''.join('[%s]' % ' '.join(rr) for rr in rrs))
    resp = self.Response(code, mesg, timing)

    resp.rrs = rrs

    return resp
