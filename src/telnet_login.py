# Telnet {{{
from telnetlib import Telnet

from src.rfunctions import *
from src.custlogger import *


class Telnet_login(TCP_Cache):
  '''Brute-force Telnet'''

  usage_hints = (
    """%prog host=10.0.0.1 inputs='FILE0\\nFILE1' 0=logins.txt 1=passwords.txt persistent=0"""
    """ prompt_re='Username:|Password:' -x ignore:egrep='Login incorrect.+Username:'""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [23]'),
    ('inputs', 'list of values to input'),
    ('prompt_re', 'regular expression to match prompts [\w+:]'),
    ('timeout', 'seconds to wait for a response and for prompt_re to match received data [20]'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, timeout):
    self.prompt_count = 0
    fp = Telnet(host, int(port), int(timeout))

    return TCP_Connection(fp)

  def execute(self, host, port='23', inputs=None, prompt_re='\w+:', timeout='20', persistent='1'):
    logger = logging.getLogger(__name__)
    with Timing() as timing:
      fp, _ = self.bind(host, port, timeout=timeout)

    trace = b''
    prompt_re = b(prompt_re)
    timeout = int(timeout)

    if self.prompt_count == 0:
      _, _, raw = fp.expect([prompt_re], timeout=timeout)
      logger.debug('raw banner: %r' % raw)
      trace += raw
      self.prompt_count += 1

    if inputs is not None:
      with Timing() as timing:

        for val in inputs.split(r'\n'):
          logger.debug('input: %s' % val)
          cmd = b(val + '\n') #'\r\x00'
          fp.write(cmd)
          trace += cmd

          _, _, raw = fp.expect([prompt_re], timeout=timeout)
          logger.debug('raw %d: %r' % (self.prompt_count, raw))
          trace += raw
          self.prompt_count += 1

    if persistent == '0':
      self.reset()

    raw = B(raw)
    trace = B(trace)

    mesg = repr(raw)[1:-1] # strip enclosing single quotes
    return self.Response(0, mesg, timing, trace)

# }}}
