from src.ftp_login import FTP_login
from src.ssh_login import SSH_login
from src.telnet_login import Telnet_login
from src.dns_forward import *
from src.rfunctions import *
from models import *


modules = [
  ('ftp_login', (Controller, FTP_login)),
  ('ssh_login', (Controller, SSH_login)),
  ('telnet_login', (Controller, Telnet_login)),
  # ('smtp_login', (Controller, SMTP_login)),
  # ('smtp_vrfy', (Controller, SMTP_vrfy)),
  # ('smtp_rcpt', (Controller, SMTP_rcpt)),
  # ('finger_lookup', (Controller_Finger, Finger_lookup)),
  # ('http_fuzz', (Controller_HTTP, HTTP_fuzz)),
  # ('ajp_fuzz', (Controller, AJP_fuzz)),
  # ('pop_login', (Controller, POP_login)),
  # ('pop_passd', (Controller, POP_passd)),
  # ('imap_login', (Controller, IMAP_login)),
  # ('ldap_login', (Controller, LDAP_login)),
  # ('smb_login', (Controller, SMB_login)),
  # ('smb_lookupsid', (Controller, SMB_lookupsid)),
  # ('rlogin_login', (Controller, Rlogin_login)),
  # ('vmauthd_login', (Controller, VMauthd_login)),
  # ('mssql_login', (Controller, MSSQL_login)),
  # ('oracle_login', (Controller, Oracle_login)),
  # ('mysql_login', (Controller, MySQL_login)),
  # ('mysql_query', (Controller, MySQL_query)),
  # ('rdp_login', (Controller, RDP_login)),
  # ('pgsql_login', (Controller, Pgsql_login)),
  # ('vnc_login', (Controller, VNC_login)),

  ('dns_forward', (Controller_DNS, DNS_forward)),
  ('dns_reverse', (Controller_DNS, DNS_reverse)),
  # ('snmp_login', (Controller, SNMP_login)),
  # ('ike_enum', (Controller_IKE, IKE_enum)),
  #
  # ('unzip_pass', (Controller, Unzip_pass)),
  # ('keystore_pass', (Controller, Keystore_pass)),
  # ('sqlcipher_pass', (Controller, SQLCipher_pass)),
  # ('umbraco_crack', (Controller, Umbraco_crack)),
  #
  # ('tcp_fuzz', (Controller, TCP_fuzz)),
  # ('dummy_test', (Controller, Dummy_test)),
  ]

dependencies = {
  'paramiko': [('ssh_login',), 'http://www.paramiko.org/', '1.7.7.1'],
  'pycurl': [('http_fuzz',), 'http://pycurl.io/', '7.43.0'],
  'libcurl': [('http_fuzz',), 'https://curl.haxx.se/', '7.21.0'],
  'ajpy': [('ajp_fuzz',), 'https://github.com/hypn0s/AJPy/', '0.0.1'],
  'openldap': [('ldap_login',), 'http://www.openldap.org/', '2.4.24'],
  'impacket': [('smb_login', 'smb_lookupsid', 'mssql_login'), 'https://github.com/CoreSecurity/impacket', '0.9.12'],
  'pyopenssl': [('mssql_login',), 'https://pyopenssl.org/', '17.5.0'],
  'cx_Oracle': [('oracle_login',), 'http://cx-oracle.sourceforge.net/', '5.1.1'],
  'mysqlclient': [('mysql_login',), 'https://github.com/PyMySQL/mysqlclient-python', '1.3.12'],
  'xfreerdp': [('rdp_login',), 'https://github.com/FreeRDP/FreeRDP.git', '1.2.0-beta1'],
  'psycopg': [('pgsql_login',), 'http://initd.org/psycopg/', '2.4.5'],
  'pycrypto': [('smb_login', 'smb_lookupsid', 'mssql_login', 'vnc_login',), 'http://www.dlitz.net/software/pycrypto/', '2.6.1'],
  'dnspython': [('dns_reverse', 'dns_forward'), 'http://www.dnspython.org/', '1.10.0'],
  'IPy': [('dns_reverse', 'dns_forward'), 'https://github.com/haypo/python-ipy', '0.75'],
  'pysnmp': [('snmp_login',), 'http://pysnmp.sf.net/', '4.2.1'],
  'pyasn1': [('smb_login', 'smb_lookupsid', 'mssql_login', 'snmp_login'), 'http://sourceforge.net/projects/pyasn1/', '0.1.2'],
  'ike-scan': [('ike_enum',), 'http://www.nta-monitor.com/tools-resources/security-tools/ike-scan', '1.9'],
  'unzip': [('unzip_pass',), 'http://www.info-zip.org/', '6.0'],
  'java': [('keystore_pass',), 'http://www.oracle.com/technetwork/java/javase/', '6'],
  'pysqlcipher': [('sqlcipher_pass',), 'https://github.com/leapcode/pysqlcipher/', '2.6.10'],
  'python': [('ftp_login',), 'Patator requires Python 2.7 or above. Some features may be unavailable otherwise, such as TLS support for FTP.'],
  }
# }}}

# main {{{
if __name__ == '__main__':
  multiprocessing.freeze_support()
  def show_usage():
    # print(__banner__)
    print('''Usage: patator.py module --help

Available modules:
%s''' % '\n'.join('  + %-13s : %s' % (k, v[1].__doc__) for k, v in modules))

    sys.exit(2)

  available = dict(modules)
  name = os.path.basename(sys.argv[0]).lower()
  if name not in available:
    if len(sys.argv) == 1:
      show_usage()

    name = os.path.basename(sys.argv[1]).lower()
    if name not in available:
      show_usage()

    del sys.argv[0]

  # dependencies
  abort = False
  for k in set(notfound):
    args = dependencies[k]
    if name in args[0]:
      if len(args) == 2:
        print('WARNING: %s' % args[1])
      else:
        url, ver = args[1:]
        print('ERROR: %s %s (%s) is required to run %s.' % (k, ver, url, name))
        abort = True

  if abort:
    print('Please read the README inside for more information.')
    sys.exit(3)

#  print(sys.argv[1:])
  # start
  ctrl, module = available[name]
  powder = ctrl(module, [name] + sys.argv[1:])
  powder.fire()
# }}}

# vim: ts=2 sw=2 sts=2 et fdm=marker bg=dark
