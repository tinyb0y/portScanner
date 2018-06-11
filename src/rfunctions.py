__author__="tinyb0y"
__git__     = 'https://github.com/tinyb0y/portScanner'
__version__ = '0.1'
__banner__  = 'PortScanner v%s (%s)' % (__version__, __git__)

# imports {{{
import ctypes
import glob
import hashlib
import re
import signal
import string
import subprocess
import sys
from base64 import b64encode
from datetime import timedelta, datetime
from decimal import Decimal
from functools import reduce
from itertools import islice
from platform import system
from select import select
from time import localtime, gmtime, strftime, sleep, time

from src.custlogger import Logger

try:
  # python3+
  from queue import Empty, Full
  from urllib.parse import quote, urlencode, urlparse, urlunparse, parse_qsl, quote_plus
  from io import StringIO
  from sys import maxsize as maxint
except ImportError:
  # python2.6+
  from Queue import Empty, Full
  from urllib import quote, urlencode, quote_plus
  from urlparse import urlparse, urlunparse, parse_qsl
  from cStringIO import StringIO
  from sys import maxint


import multiprocessing
from xml.sax.saxutils import escape as xmlescape, quoteattr as xmlquoteattr
import os

import logging
class TXTFormatter(logging.Formatter):
  def __init__(self, indicatorsfmt):
    self.resultfmt = '%(asctime)s %(name)-7s %(levelname)7s - ' + ' '.join('%%(%s)%ss' % (k, v) for k, v in indicatorsfmt) + ' | %(candidate)-34s | %(num)5s | %(mesg)s'

    logging.Formatter.__init__(self, datefmt='%H:%M:%S')

  def format(self, record):
    if not record.msg or record.msg == 'headers':
      fmt = self.resultfmt

      if not all(True if 0x20 <= ord(c) < 0x7f else False for c in record.candidate):
        record.candidate = repr(record.candidate)

    else:
      if record.levelno == logging.DEBUG:
        fmt = '%(asctime)s %(name)-7s %(levelname)7s [%(pname)s] %(message)s'
      else:
        fmt = '%(asctime)s %(name)-7s %(levelname)7s - %(message)s'

    if PY3:
      self._style._fmt = fmt
    else:
      self._fmt = fmt

    return logging.Formatter.format(self, record)

class CSVFormatter(logging.Formatter):
  def __init__(self, indicatorsfmt):
    fmt = '%(asctime)s,%(levelname)s,'+','.join('%%(%s)s' % name for name, _ in indicatorsfmt)+',%(candidate)s,%(num)s,%(mesg)s'

    logging.Formatter.__init__(self, fmt, datefmt='%H:%M:%S')

  def format(self, record):
    for k in ['candidate', 'mesg']:
      record.__dict__[k] = '"%s"' % record.__dict__[k].replace('"', '""')
    return logging.Formatter.format(self, record)

class XMLFormatter(logging.Formatter):
  def __init__(self, indicatorsfmt):
    fmt = '''<result time="%(asctime)s" level="%(levelname)s">
''' + '\n'.join('  <{0}>%({1})s</{0}>'.format(name.replace(':', '_'), name) for name, _ in indicatorsfmt) + '''
  <candidate>%(candidate)s</candidate>
  <num>%(num)s</num>
  <mesg>%(mesg)s</mesg>
  <target %(target)s/>
</result>'''

    logging.Formatter.__init__(self, fmt, datefmt='%H:%M:%S')

  def format(self, record):

    for k, v in record.__dict__.items():
      if isinstance(v, str):
        record.__dict__[k] = xmlescape(v)

    return super(XMLFormatter, self).format(record)

class MsgFilter(logging.Filter):

  def filter(self, record):
    if record.msg:
      return 0
    else:
      return 1

def process_logs(queue, indicatorsfmt, argv, log_dir):

  ignore_ctrlc()

  try:
    # python3
    logging._levelToName[logging.ERROR] = 'FAIL'
  except:
    # python2
    logging._levelNames[logging.ERROR] = 'FAIL'

  handler_out = logging.StreamHandler()
  handler_out.setFormatter(TXTFormatter(indicatorsfmt))


  logger = logging.getLogger(__author__)
  logger.setLevel(logging.DEBUG)
  logger.addHandler(handler_out)

  names = [name for name, _ in indicatorsfmt] + ['candidate', 'num', 'mesg']

  if log_dir:
    runtime_log = os.path.join(log_dir, 'RUNTIME.log')
    results_csv = os.path.join(log_dir, 'RESULTS.csv')
    results_xml = os.path.join(log_dir, 'RESULTS.xml')

    with open(runtime_log, 'a') as f:
      f.write('$ %s\n' % ' '.join(argv))

    if not os.path.exists(results_csv):
      with open(results_csv, 'w') as f:
        f.write('time,level,%s\n' % ','.join(names))

    if not os.path.exists(results_xml):
      with open(results_xml, 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<root>\n')
        f.write('<start utc=%s local=%s/>\n' % (xmlquoteattr(strfutctime()), xmlquoteattr(strflocaltime())))
        f.write('<cmdline>%s</cmdline>\n' % xmlescape(' '.join(argv)))
        f.write('<module>%s</module>\n' % xmlescape(argv[0]))
        f.write('<options>\n')

        i = 0
        del argv[0]
        while i < len(argv):
          arg = argv[i]
          if arg[0] == '-':
            if arg in ('-d', '--debug', '--allow-ignore-failures'):
              f.write('  <option type="global" name=%s/>\n' % xmlquoteattr(arg))
            else:
              if not arg.startswith('--') and len(arg) > 2:
                name, value = arg[:2], arg[2:]
              elif '=' in arg:
                name, value = arg.split('=', 1)
              else:
                name, value = arg, argv[i+1]
                i += 1
              f.write('  <option type="global" name=%s>%s</option>\n' % (xmlquoteattr(name), xmlescape(value)))
          else:
            name, value = arg.split('=', 1)
            f.write('  <option type="module" name=%s>%s</option>\n' % (xmlquoteattr(name), xmlescape(value)))
          i += 1
        f.write('</options>\n')
        f.write('<results>\n')

    else: # remove "</results>...</root>"
      with open(results_xml, 'r+b') as f:
        offset = f.read().find(b'</results>')
        if offset != -1:
          f.seek(offset)
          f.truncate(f.tell())

    handler_log = logging.FileHandler(runtime_log)
    handler_csv = logging.FileHandler(results_csv)
    handler_xml = logging.FileHandler(results_xml)

    handler_csv.addFilter(MsgFilter())
    handler_xml.addFilter(MsgFilter())

    handler_log.setFormatter(TXTFormatter(indicatorsfmt))
    handler_csv.setFormatter(CSVFormatter(indicatorsfmt))
    handler_xml.setFormatter(XMLFormatter(indicatorsfmt))

    logger.addHandler(handler_log)
    logger.addHandler(handler_csv)
    logger.addHandler(handler_xml)

  while True:

    pname, action, args = queue.get()

    if action == 'quit':
      if log_dir:
        with open(os.path.join(log_dir, 'RESULTS.xml'), 'a') as f:
          f.write('</results>\n<stop utc=%s local=%s/>\n</root>\n' % (xmlquoteattr(strfutctime()), xmlquoteattr(strflocaltime())))
      break

    elif action == 'headers':

      logger.info(' '*77)
      logger.info('headers', extra=dict((n, n) for n in names))
      logger.info('-'*77)

    elif action == 'result':

      typ, resp, candidate, num = args

      results = [(name, value) for (name, _), value in zip(indicatorsfmt, resp.indicators())]
      results += [('candidate', candidate), ('num', num), ('mesg', str(resp)), ('target', resp.str_target())]

      if typ == 'fail':
        logger.error(None, extra=dict(results))
      else:
        logger.info(None, extra=dict(results))

    elif action == 'save':

      resp, num = args

      if log_dir:
        filename = '%d_%s' % (num, '-'.join(map(str, resp.indicators())))
        with open('%s.txt' % os.path.join(log_dir, filename), 'w') as f:
          f.write(resp.dump())

    elif action == 'setLevel':
      logger.setLevel(args[0])

    else: # 'warn', 'info', 'debug'
      getattr(logger, action)(args[0], extra={'pname': pname})

# }}}


PY3 = sys.version_info >= (3,)
if PY3: # http://python3porting.com/problems.html
  def b(x):
    return x.encode('ISO-8859-1')
  def B(x):
    return x.decode()
else:
  def b(x):
    return x
  def B(x):
    return x

# try:
#    input = raw_input
# except NameError:
#    pass

notfound = []
try:
  from IPy import IP
  has_ipy = True
except ImportError:
  has_ipy = False
  notfound.append('IPy')

try:
  # Python 3.4+
  if sys.platform.startswith('win'):
    import multiprocessing.popen_spawn_win32 as forking
  else:
    import multiprocessing.popen_fork as forking
except ImportError:
  import multiprocessing.forking as forking

if sys.platform.startswith('win'):
  # First define a modified version of Popen.
  class _Popen(forking.Popen):
    def __init__(self, *args, **kw):
      if hasattr(sys, 'frozen'):
        # We have to set original _MEIPASS2 value from sys._MEIPASS
        # to get --onefile mode working.
        os.putenv('_MEIPASS2', sys._MEIPASS)
      try:
        super(_Popen, self).__init__(*args, **kw)
      finally:
        if hasattr(sys, 'frozen'):
          # On some platforms (e.g. AIX) 'os.unsetenv()' is not
          # available. In those cases we cannot delete the variable
          # but only set it to the empty string. The bootloader
          # can handle this case.
          if hasattr(os, 'unsetenv'):
            os.unsetenv('_MEIPASS2')
          else:
            os.putenv('_MEIPASS2', '')

  # Second override 'Popen' class with our modified version.
  forking.Popen = _Popen

from multiprocessing.managers import SyncManager
# imports }}}

# utils {{{
def expand_path(s):
    return os.path.expandvars(os.path.expanduser(s))

def strfutctime():
  return strftime("%Y-%m-%d %H:%M:%S", gmtime())

def strflocaltime():
  return strftime("%Y-%m-%d %H:%M:%S %Z", localtime())

def which(program):
  def is_exe(fpath):
    return os.path.exists(fpath) and os.access(fpath, os.X_OK)

  fpath, fname = os.path.split(program)
  if on_windows() and fname[-4:] != '.exe' :
    fname += '.exe'

  if fpath:
    if is_exe(program):
      return program
  else:
    for path in os.environ["PATH"].split(os.pathsep):
      exe_file = os.path.join(path, fname)
      if is_exe(exe_file):
        return exe_file

  return None

def build_logdir(opt_dir, opt_auto):
    if opt_auto:
      return create_time_dir(opt_dir or '/tmp/patator', opt_auto)
    elif opt_dir:
      return create_dir(opt_dir)
    else:
      return None

def create_dir(top_path):
  top_path = os.path.abspath(top_path)
  if os.path.isdir(top_path):
    files = os.listdir(top_path)
    if files:
      if input("Directory '%s' is not empty, do you want to wipe it ? [Y/n]: " % top_path) != 'n':
        for root, dirs, files in os.walk(top_path):
          if dirs:
            print("Directory '%s' contains sub-directories, safely aborting..." % root)
            sys.exit(0)
          for f in files:
            os.unlink(os.path.join(root, f))
          break
  else:
    os.mkdir(top_path)
  return top_path

def create_time_dir(top_path, desc):
  now = localtime()
  date, time = strftime('%Y-%m-%d', now), strftime('%H%M%S', now)
  top_path = os.path.abspath(top_path)
  date_path = os.path.join(top_path, date)
  time_path = os.path.join(top_path, date, time + '_' + desc)

  if not os.path.isdir(top_path):
    os.makedirs(top_path)
  if not os.path.isdir(date_path):
    os.mkdir(date_path)
  if not os.path.isdir(time_path):
    os.mkdir(time_path)

  return time_path

def pprint_seconds(seconds, fmt):
  return fmt % reduce(lambda x,y: divmod(x[0], y) + x[1:], [(seconds,),60,60])

def md5hex(plain):
  return hashlib.md5(plain).hexdigest()

def sha1hex(plain):
  return hashlib.sha1(plain).hexdigest()

# I rewrote itertools.product to avoid memory over-consumption when using large wordlists
def product(xs, *rest):
  if len(rest) == 0:
    for x in xs():
      yield [x]
  else:
    for head in xs():
      for tail in product(*rest):
        yield [head] + tail

def chain(*iterables):
  def xs():
    for iterable in iterables:
      for element in iterable:
        yield element
  return xs

class FileIter:
  def __init__(self, filename):
    self.filename = filename

  def __iter__(self):
    return open(self.filename)

def padhex(d):
  x = '%x' % d
  return '0' * (len(x) % 2) + x

# These are examples. You can easily write your own iterator to fit your needs.
# Or using the PROG keyword, you can call an external program such as:
#   - seq(1) from coreutils
#   - http://hashcat.net/wiki/doku.php?id=maskprocessor
#   - john -stdout -i
# For example:
# $ ./dummy_test data=PROG0 0='seq 1 80'
# $ ./dummy_test data=PROG0 0='mp64.bin ?l?l?l',$(mp64.bin --combination ?l?l?l)
class RangeIter:

  def __init__(self, typ, rng, random=None):
    if typ not in ['hex', 'int', 'float', 'letters', 'lower', 'lowercase', 'upper', 'uppercase']:
      raise ValueError('Incorrect range type %r' % typ)

    if typ in ('hex', 'int', 'float'):

      m = re.match('(-?[^-]+)-(-?[^-]+)$', rng) # 5-50 or -5-50 or 5--50 or -5--50
      if not m:
        raise ValueError('Unsupported range %r' % rng)

      mn = m.group(1)
      mx = m.group(2)

      if typ in ('hex', 'int'):

        mn = int(mn, 16 if '0x' in mn else 10)
        mx = int(mx, 16 if '0x' in mx else 10)

        if typ == 'hex':
          fmt = padhex
        elif typ == 'int':
          fmt = '%d'

      elif typ == 'float':
        mn = Decimal(mn)
        mx = Decimal(mx)

      if mn > mx:
        step = -1
      else:
        step = 1

    elif typ == 'letters':
      charset = [c for c in string.letters]

    elif typ in ('lower', 'lowercase'):
      charset = [c for c in string.lowercase]

    elif typ in ('upper', 'uppercase'):
      charset = [c for c in string.uppercase]

    def zrange(start, stop, step, fmt):
      x = start
      while x != stop+step:

        if callable(fmt):
          yield fmt(x)
        else:
          yield fmt % x
        x += step

    def letterrange(first, last, charset):
      for k in range(len(last)):
        for x in product(*[chain(charset)]*(k+1)):
          result = ''.join(x)
          if first:
            if first != result:
              continue
            else:
              first = None
          yield result
          if result == last:
            return

    if typ == 'float':
      precision = max(len(str(x).partition('.')[-1]) for x in (mn, mx))

      fmt = '%%.%df' % precision
      exp = 10**precision
      step *= Decimal(1) / exp

      self.generator = zrange, (mn, mx, step, fmt)
      self.size = int(abs(mx-mn) * exp) + 1

      def random_generator():
        while True:
          yield fmt % (Decimal(random.randint(mn*exp, mx*exp)) / exp)

    elif typ in ('hex', 'int'):
      self.generator = zrange, (mn, mx, step, fmt)
      self.size = abs(mx-mn) + 1

      def random_generator():
        while True:
          yield fmt % random.randint(mn, mx)

    else: # letters, lower, upper
      def count(f):
        total = 0
        i = 0
        for c in f[::-1]:
          z = charset.index(c) + 1
          total += (len(charset)**i)*z
          i += 1
        return total + 1

      first, last = rng.split('-')
      self.generator = letterrange, (first, last, charset)
      self.size = count(last) - count(first) + 1

    if random:
      self.generator = random_generator, ()
      self.size = maxint

  def __iter__(self):
    fn, args = self.generator
    return fn(*args)

  def __len__(self):
    return self.size

class ProgIter:

  def __init__(self, prog):
    self.prog = prog

  def __iter__(self):
    p = subprocess.Popen(self.prog.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout

class Progress:
  def __init__(self):
    self.current = ''
    self.done_count = 0
    self.hits_count = 0
    self.skip_count = 0
    self.fail_count = 0
    self.seconds = [1]*25 # avoid division by zero early bug condition

class TimeoutError(Exception):
  pass

def on_windows():
  return 'Win' in system()

def ignore_ctrlc():
  if on_windows():
    ctypes.windll.kernel32.SetConsoleCtrlHandler(0, 1)
  else:
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def handle_alarm():
  if not on_windows():
    signal.signal(signal.SIGALRM, raise_timeout)

def raise_timeout(signum, frame):
  if signum == signal.SIGALRM:
    raise TimeoutError('timed out')

def enable_alarm(timeout):
  if not on_windows():
    signal.alarm(timeout)

def disable_alarm():
  if not on_windows():
     signal.alarm(0)

# SyncManager.start(initializer) only available since python2.7
class MyManager(SyncManager):
  @classmethod
  def _run_server(cls, registry, address, authkey, serializer, writer, initializer=None, initargs=()):
    ignore_ctrlc()
    super(MyManager, cls)._run_server(registry, address, authkey, serializer, writer)

# }}}

# Controller {{{
class Controller:

  builtin_actions = (
    ('ignore', 'do not report'),
    ('retry', 'try payload again'),
    ('free', 'dismiss future similar payloads'),
    ('quit', 'terminate execution now'),
    )

  available_encodings = {
    'hex': (lambda s: s.encode('hex'), 'encode in hexadecimal'),
    'unhex': (lambda s: s.decode('hex'), 'decode from hexadecimal'),
    'b64': (b64encode, 'encode in base64'),
    'md5': (md5hex, 'hash in md5'),
    'sha1': (sha1hex, 'hash in sha1'),
    'url': (quote_plus, 'url encode'),
    }

  def expand_key(self, arg):
    yield arg.split('=', 1)

  def find_file_keys(self, value):
    return map(int, re.findall(r'FILE(\d)', value))

  def find_net_keys(self, value):
    return map(int, re.findall(r'NET(\d)', value))

  def find_combo_keys(self, value):
    return [map(int, t) for t in re.findall(r'COMBO(\d)(\d)', value)]

  def find_module_keys(self, value):
    return map(int, re.findall(r'MOD(\d)', value))

  def find_range_keys(self, value):
    return map(int, re.findall(r'RANGE(\d)', value))

  def find_prog_keys(self, value):
    return map(int, re.findall(r'PROG(\d)', value))

  def usage_parser(self, name):
    from optparse import OptionParser
    from optparse import OptionGroup
    from optparse import IndentedHelpFormatter

    class MyHelpFormatter(IndentedHelpFormatter):
      def format_epilog(self, epilog):
        return epilog

      def format_heading(self, heading):
        if self.current_indent == 0 and heading == 'Options':
          heading = 'Global options'
        return "%*s%s:\n" % (self.current_indent, "", heading)

      def format_usage(self, usage):
        return '%s\nUsage: %s\n' % (__banner__, usage)

    available_actions = self.builtin_actions + self.module.available_actions
    available_conditions = self.module.Response.available_conditions

    usage = '''%%prog <module-options ...> [global-options ...]

Examples:
  %s''' % '\n  '.join(self.module.usage_hints)

    usage += '''

Module options:
%s ''' % ('\n'.join('  %-14s: %s' % (k, v) for k, v in self.module.available_options))

    epilog = '''
Syntax:
 -x actions:conditions

    actions    := action[,action]*
    action     := "%s"
    conditions := condition=value[,condition=value]*
    condition  := "%s"
''' % ('" | "'.join(k for k, v in available_actions),
       '" | "'.join(k for k, v in available_conditions))

    epilog += '''
%s

%s
''' % ('\n'.join('    %-12s: %s' % (k, v) for k, v in available_actions),
       '\n'.join('    %-12s: %s' % (k, v) for k, v in available_conditions))

    epilog += '''
For example, to ignore all redirects to the home page:
... -x ignore:code=302,fgrep='Location: /home.html'

 -e tag:encoding

    tag        := any unique string (eg. T@G or _@@_ or ...)
    encoding   := "%s"

%s''' % ('" | "'.join(k for k in self.available_encodings),
       '\n'.join('    %-12s: %s' % (k, v) for k, (f, v) in self.available_encodings.items()))

    epilog += '''

For example, to encode every password in base64:
... host=10.0.0.1 user=admin password=_@@_FILE0_@@_ -e _@@_:b64

Please read the README inside for more examples and usage information.
'''

    parser = OptionParser(usage=usage, prog=name, epilog=epilog, version=__banner__, formatter=MyHelpFormatter())

    exe_grp = OptionGroup(parser, 'Execution')
    exe_grp.add_option('-x', dest='actions', action='append', default=[], metavar='arg', help='actions and conditions, see Syntax below')
    exe_grp.add_option('--start', dest='start', type='int', default=0, metavar='N', help='start from offset N in the wordlist product')
    exe_grp.add_option('--stop', dest='stop', type='int', default=None, metavar='N', help='stop at offset N')
    exe_grp.add_option('--resume', dest='resume', metavar='r1[,rN]*', help='resume previous run')
    exe_grp.add_option('-e', dest='encodings', action='append', default=[], metavar='arg', help='encode everything between two tags, see Syntax below')
    exe_grp.add_option('-C', dest='combo_delim', default=':', metavar='str', help="delimiter string in combo files (default is ':')")
    exe_grp.add_option('-X', dest='condition_delim', default=',', metavar='str', help="delimiter string in conditions (default is ',')")
    exe_grp.add_option('--allow-ignore-failures', action='store_true', default=False, dest='allow_ignore_failures', help="failures cannot be ignored with -x (this is by design to avoid false negatives) this option overrides this behavior")

    opt_grp = OptionGroup(parser, 'Optimization')
    opt_grp.add_option('--rate-limit', dest='rate_limit', type='float', default=0, metavar='N', help='wait N seconds between each test (default is 0)')
    opt_grp.add_option('--timeout', dest='timeout', type='int', default=0, metavar='N', help='wait N seconds for a response before retrying payload (default is 0)')
    opt_grp.add_option('--max-retries', dest='max_retries', type='int', default=4, metavar='N', help='skip payload after N retries (default is 4) (-1 for unlimited)')
    opt_grp.add_option('-t', '--threads', dest='num_threads', type='int', default=10, metavar='N', help='number of threads (default is 10)')

    log_grp = OptionGroup(parser, 'Logging')
    log_grp.add_option('-l', dest='log_dir', metavar='DIR', help="save output and response data into DIR ")
    log_grp.add_option('-L', dest='auto_log', metavar='SFX', help="automatically save into DIR/yyyy-mm-dd/hh:mm:ss_SFX (DIR defaults to '/tmp/patator')")

    dbg_grp = OptionGroup(parser, 'Debugging')
    dbg_grp.add_option('-d', '--debug', dest='debug', action='store_true', default=False, help='enable debug messages')

    parser.option_groups.extend([exe_grp, opt_grp, log_grp, dbg_grp])

    return parser

  def parse_usage(self, argv):
    parser = self.usage_parser(argv[0])
    opts, args = parser.parse_args(argv[1:])

    if not len(args) > 0:
      parser.print_usage()
      print('ERROR: wrong usage. Please read the README inside for more information.')
      sys.exit(2)

    return opts, args

  def __init__(self, module, argv):
    self.thread_report = []
    self.thread_progress = []

    self.payload = {}
    self.iter_keys = {}
    self.enc_keys = []

    self.module = module

    opts, args = self.parse_usage(argv)

    self.combo_delim = opts.combo_delim
    self.condition_delim = opts.condition_delim
    self.rate_limit = opts.rate_limit
    self.timeout = opts.timeout
    self.max_retries = opts.max_retries
    self.num_threads = opts.num_threads
    self.start, self.stop = opts.start, opts.stop
    self.allow_ignore_failures = opts.allow_ignore_failures

    self.resume = [int(i) for i in opts.resume.split(',')] if opts.resume else None

    manager = MyManager()
    manager.start()

    self.ns = manager.Namespace()
    self.ns.actions = {}
    self.ns.free_list = []
    self.ns.paused = False
    self.ns.quit_now = False
    self.ns.start_time = 0
    self.ns.total_size = 1

    log_queue = multiprocessing.Queue()

    logsvc = multiprocessing.Process(name='LogSvc', target=process_logs, args=(log_queue, module.Response.indicatorsfmt, argv, build_logdir(opts.log_dir, opts.auto_log)))
    logsvc.daemon = True
    logsvc.start()

    global logger
    logger = Logger(log_queue)

    if opts.debug:
      logger.setLevel(logging.DEBUG)
    else:
      logger.setLevel(logging.INFO)

    wlists = {}
    kargs = []
    for arg in args: # ('host=NET0', '0=10.0.0.0/24', 'user=COMBO10', 'password=COMBO11', '1=combos.txt', 'name=google.MOD2', '2=TLD')
      for k, v in self.expand_key(arg):
        logger.debug('k: %s, v: %s' % (k, v))

        if k.isdigit():
          wlists[k] = v

        else:
          if v.startswith('@'):
            p = expand_path(v[1:])
            with open(p) as f:
              v = f.read()

          kargs.append((k, v))

    iter_vals = [v for k, v in sorted(wlists.items())]
    logger.debug('kargs: %s' % kargs) # [('host', 'NET0'), ('user', 'COMBO10'), ('password', 'COMBO11'), ('domain', 'MOD2')]
    logger.debug('iter_vals: %s' % iter_vals) # ['10.0.0.0/24', 'combos.txt', 'TLD']

    for k, v in kargs:

      for e in opts.encodings:
        meta, enc = e.split(':')
        if re.search(r'{0}.+?{0}'.format(meta), v):
          self.enc_keys.append((k, meta, self.available_encodings[enc][0]))

      for i in self.find_file_keys(v):
        if i not in self.iter_keys:
          self.iter_keys[i] = ('FILE', iter_vals[i], [])
        self.iter_keys[i][2].append(k)

      else:
        for i in self.find_net_keys(v):
          if i not in self.iter_keys:
            self.iter_keys[i] = ('NET', iter_vals[i], [])
          self.iter_keys[i][2].append(k)

          if not has_ipy:
            print('IPy (https://github.com/haypo/python-ipy) is required for using NET keyword.')
            print('Please read the README inside for more information.')
            sys.exit(3)

        else:
          for i, j in self.find_combo_keys(v):
            if i not in self.iter_keys:
              self.iter_keys[i] = ('COMBO', iter_vals[i], [])
            self.iter_keys[i][2].append((j, k))

          else:
            for i in self.find_module_keys(v):
              if i not in self.iter_keys:
                self.iter_keys[i] = ('MOD', iter_vals[i], [])
              self.iter_keys[i][2].append(k)

            else:
              for i in self.find_range_keys(v):
                if i not in self.iter_keys:
                  self.iter_keys[i] = ('RANGE', iter_vals[i], [])
                self.iter_keys[i][2].append(k)

              else:
                for i in self.find_prog_keys(v):
                  if i not in self.iter_keys:
                    self.iter_keys[i] = ('PROG', iter_vals[i], [])
                  self.iter_keys[i][2].append(k)

                else:
                  self.payload[k] = v

    logger.debug('iter_keys: %s' % self.iter_keys) # { 0: ('NET', '10.0.0.0/24', ['host']), 1: ('COMBO', 'combos.txt', [(0, 'user'), (1, 'password')]), 2: ('MOD', 'TLD', ['name'])
    logger.debug('enc_keys: %s' % self.enc_keys) # [('password', 'ENC', hex), ('header', 'B64', b64encode), ...
    logger.debug('payload: %s' % self.payload)

    self.available_actions = [k for k, _ in self.builtin_actions + self.module.available_actions]
    self.module_actions = [k for k, _ in self.module.available_actions]

    for x in opts.actions:
      self.update_actions(x)

    logger.debug('actions: %s' % self.ns.actions)

  def update_actions(self, arg):
    ns_actions = self.ns.actions

    actions, conditions = arg.split(':', 1)
    for action in actions.split(','):

      conds = [c.split('=', 1) for c in conditions.split(self.condition_delim)]

      if '=' in action:
        name, opts = action.split('=')
      else:
        name, opts = action, None

      if name not in self.available_actions:
        raise ValueError('Unsupported action %r' % name)

      if name not in ns_actions:
        ns_actions[name] = []

      ns_actions[name].append((conds, opts))

    self.ns.actions = ns_actions

  def lookup_actions(self, resp):
    actions = {}
    for action, conditions in self.ns.actions.items():
      for condition, opts in conditions:
        for key, val in condition:
          if key[-1] == '!':
            if resp.match(key[:-1], val):
              break
          else:
            if not resp.match(key, val):
              break
        else:
          actions[action] = opts
    return actions

  def check_free(self, payload):
    # free_list: 'host=10.0.0.1', 'user=anonymous', 'host=10.0.0.7,user=test', ...
    for m in self.ns.free_list:
      args = m.split(',', 1)
      for arg in args:
        k, v = arg.split('=', 1)
        if payload[k] != v:
          break
      else:
        return True

    return False

  def register_free(self, payload, opts):
    self.ns.free_list += [','.join('%s=%s' % (k, payload[k]) for k in opts.split('+'))]
    logger.debug('free_list updated: %s' % self.ns.free_list)

  def fire(self):
    logger.info('Starting %s at %s' % (__banner__, strftime('%Y-%m-%d %H:%M %Z', localtime())))

    try:
      self.start_threads()
      self.monitor_progress()
    except KeyboardInterrupt:
      pass
    except:
      logging.exception(sys.exc_info()[1])
    finally:
      self.ns.quit_now = True

    try:
      # waiting for reports enqueued by consumers to be flushed
      while True:
        active = multiprocessing.active_children()
        self.report_progress()
        if not len(active) > 2: # SyncManager and LogSvc
          break
        logger.debug('active: %s' % active)
        sleep(.1)
    except KeyboardInterrupt:
      pass

    if self.ns.total_size >= maxint:
      total_size = -1
    else:
      total_size = self.ns.total_size

    total_time = time() - self.ns.start_time

    hits_count = sum(p.hits_count for p in self.thread_progress)
    done_count = sum(p.done_count for p in self.thread_progress)
    skip_count = sum(p.skip_count for p in self.thread_progress)
    fail_count = sum(p.fail_count for p in self.thread_progress)

    speed_avg = done_count / total_time

    self.show_final()

    logger.info('Hits/Done/Skip/Fail/Size: %d/%d/%d/%d/%d, Avg: %d r/s, Time: %s' % (
      hits_count, done_count, skip_count, fail_count, total_size, speed_avg,
      pprint_seconds(total_time, '%dh %dm %ds')))

    if done_count < total_size:
      resume = []
      for i, p in enumerate(self.thread_progress):
        c = p.done_count + p.skip_count
        if self.resume:
          if i < len(self.resume):
            c += self.resume[i]
        resume.append(str(c))

      logger.info('To resume execution, pass --resume %s' % ','.join(resume))

    logger.quit()
    while len(multiprocessing.active_children()) > 1:
      sleep(.1)

  def push_final(self, resp): pass
  def show_final(self): pass

  def start_threads(self):

    task_queues = [multiprocessing.Queue(maxsize=10000) for _ in range(self.num_threads)]

    # consumers
    for num in range(self.num_threads):
      report_queue = multiprocessing.Queue(maxsize=1000)
      t = multiprocessing.Process(name='Consumer-%d' % num, target=self.consume, args=(task_queues[num], report_queue, logger.queue))
      t.daemon = True
      t.start()
      self.thread_report.append(report_queue)
      self.thread_progress.append(Progress())

    # producer
    t = multiprocessing.Process(name='Producer', target=self.produce, args=(task_queues, logger.queue))
    t.daemon = True
    t.start()

  def produce(self, task_queues, log_queue):

    ignore_ctrlc()

    global logger
    logger = Logger(log_queue)

    iterables = []
    total_size = 1

    def abort(msg):
      logger.warn(msg)
      self.ns.quit_now = True

    for _, (t, v, _) in self.iter_keys.items():

      if t in ('FILE', 'COMBO'):
        size = 0
        files = []

        for name in v.split(','):
          for fpath in sorted(glob.iglob(expand_path(name))):
            if not os.path.isfile(fpath):
              return abort("No such file '%s'" % fpath)

            with open(fpath) as f:
              for _ in f:
                size += 1

            files.append(FileIter(fpath))

        iterable = chain(*files)

      elif t == 'NET':
        subnets = [IP(n, make_net=True) for n in v.split(',')]
        size = sum(len(s) for s in subnets)
        iterable = chain(*subnets)

      elif t == 'MOD':
        elements, size = self.module.available_keys[v]()
        iterable = chain(elements)

      elif t == 'RANGE':
        size = 0
        ranges = []

        for r in v.split(','):
          typ, opt = r.split(':', 1)

          try:
            it = RangeIter(typ, opt)
            size += len(it)
          except ValueError as e:
            return abort("Invalid range '%s' of type '%s', %s" % (opt, typ, e))

          ranges.append(it)

        iterable = chain(*ranges)

      elif t == 'PROG':
        m = re.match(r'(.+),(\d+)$', v)
        if m:
          prog, size = m.groups()
        else:
          prog, size = v, maxint

        logger.debug('prog: %s, size: %s' % (prog, size))

        it = ProgIter(prog)
        iterable, size = chain(it), int(size)

      else:
        return abort('Incorrect keyword %r' % t)

      total_size *= size
      iterables.append(iterable)

    if not iterables:
      iterables.append(chain(['']))

    if self.stop:
      total_size = self.stop - self.start
    else:
      total_size -= self.start

    if self.resume:
      total_size -= sum(self.resume)

    self.ns.total_size = total_size
    self.ns.start_time = time()

    logger.headers()

    count = 0
    for pp in islice(product(*iterables), self.start, self.stop):

      if self.ns.quit_now:
        break

      cid = count % self.num_threads
      prod = [str(p).rstrip('\r\n') for p in pp]

      if self.resume:
        idx = count % len(self.resume)
        off = self.resume[idx]

        if count < off * len(self.resume):
          #logger.debug('Skipping %d %s, resume[%d]: %s' % (count, ':'.join(prod), idx, self.resume[idx]))
          count += 1
          continue

      while True:
        if self.ns.quit_now:
          break

        try:
          task_queues[cid].put_nowait(prod)
          break
        except Full:
          sleep(.1)

      count += 1

    if not self.ns.quit_now:
      for q in task_queues:
        q.put(None)

    logger.debug('producer done')

    while True:
      if self.ns.quit_now:
        for q in task_queues:
          q.cancel_join_thread()
        break
      sleep(.5)

    logger.debug('producer exits')

  def consume(self, task_queue, report_queue, log_queue):

    ignore_ctrlc()
    handle_alarm()

    global logger
    logger = Logger(log_queue)

    module = self.module()

    def shutdown():
      if hasattr(module, '__del__'):
        module.__del__()
      logger.debug('consumer done')

    while True:
      if self.ns.quit_now:
        return shutdown()

      try:
        prod = task_queue.get_nowait()
      except Empty:
        sleep(.1)
        continue

      if prod is None:
        return shutdown()

      payload = self.payload.copy()

      for i, (t, _, keys) in self.iter_keys.items():
        if t == 'FILE':
          for k in keys:
            payload[k] = payload[k].replace('FILE%d' % i, prod[i])
        elif t == 'NET':
          for k in keys:
            payload[k] = payload[k].replace('NET%d' % i, prod[i])
        elif t == 'COMBO':
          for j, k in keys:
            payload[k] = payload[k].replace('COMBO%d%d' % (i, j), prod[i].split(self.combo_delim)[j])
        elif t == 'MOD':
          for k in keys:
            payload[k] = payload[k].replace('MOD%d' %i, prod[i])
        elif t == 'RANGE':
          for k in keys:
            payload[k] = payload[k].replace('RANGE%d' %i, prod[i])
        elif t == 'PROG':
          for k in keys:
            payload[k] = payload[k].replace('PROG%d' %i, prod[i])

      for k, m, e in self.enc_keys:
        payload[k] = re.sub(r'{0}(.+?){0}'.format(m), lambda m: e(m.group(1)), payload[k])

      logger.debug('product: %s' % prod)
      pp_prod = ':'.join(prod)

      if self.check_free(payload):
        report_queue.put(('skip', pp_prod, None, 0))
        continue

      try_count = 0
      start_time = time()

      while True:

        while self.ns.paused and not self.ns.quit_now:
          sleep(1)

        if self.ns.quit_now:
          return shutdown()

        if self.rate_limit > 0:
          sleep(self.rate_limit)

        if try_count <= self.max_retries or self.max_retries < 0:

          actions = {}
          try_count += 1

          logger.debug('payload: %s [try %d/%d]' % (payload, try_count, self.max_retries+1))

          try:
            enable_alarm(self.timeout)
            resp = module.execute(**payload)

            disable_alarm()
          except:
            disable_alarm()

            mesg = '%s %s' % sys.exc_info()[:2]
            logger.debug('caught: %s' % mesg)

            #logging.exception(sys.exc_info()[1])

            resp = self.module.Response('xxx', mesg, timing=time()-start_time)

            if hasattr(module, 'reset'):
              module.reset()

            sleep(try_count * .1)
            continue

        else:
          actions = {'fail': None}

        actions.update(self.lookup_actions(resp))
        report_queue.put((actions, pp_prod, resp, time() - start_time))

        for name in self.module_actions:
          if name in actions:
            getattr(module, name)(**payload)

        if 'free' in actions:
          self.register_free(payload, actions['free'])
          break

        if 'fail' in actions:
          break

        if 'retry' in actions:
          continue

        break

  def monitor_progress(self):
    # loop until SyncManager, LogSvc and Producer are the only children left alive
    while len(multiprocessing.active_children()) > 3 and not self.ns.quit_now:
      self.report_progress()
      self.monitor_interaction()

  def report_progress(self):
    for i, pq in enumerate(self.thread_report):
      p = self.thread_progress[i]

      while True:

        try:
          actions, current, resp, seconds = pq.get_nowait()
          #logger.info('actions reported: %s' % '+'.join(actions))

        except Empty:
          break

        if actions == 'skip':
          p.skip_count += 1
          continue

        if self.resume:
          offset = p.done_count + self.resume[i]
        else:
          offset = p.done_count

        offset = (offset * self.num_threads) + i + 1 + self.start

        p.current = current
        p.seconds[p.done_count % len(p.seconds)] = seconds

        if 'fail' in actions:
          if not self.allow_ignore_failures or 'ignore' not in actions:
            logger.result('fail', resp, current, offset)

        elif 'ignore' not in actions:
          logger.result('hit', resp, current, offset)

        if 'fail' in actions:
          p.fail_count += 1

        elif 'retry' in actions:
          continue

        elif 'ignore' not in actions:
          p.hits_count += 1

          logger.save(resp, offset)

          self.push_final(resp)

        p.done_count += 1

        if 'quit' in actions:
          self.ns.quit_now = True


  def monitor_interaction(self):

    if on_windows():
      import msvcrt
      if not msvcrt.kbhit():
        sleep(.1)
        return

      command = msvcrt.getche()
      if command == 'x':
        command += input()

    else:
      i, _, _ = select([sys.stdin], [], [], .1)
      if not i: return
      command = i[0].readline().strip()

    if command == 'h':
      logger.info('''Available commands:
       h       show help
       <Enter> show progress
       d/D     increase/decrease debug level
       p       pause progress
       f       show verbose progress
       x arg   add monitor condition
       a       show all active conditions
       q       terminate execution now
       ''')

    elif command == 'q':
      self.ns.quit_now = True

    elif command == 'p':
      self.ns.paused = not self.ns.paused
      logger.info(self.ns.paused and 'Paused' or 'Unpaused')

    elif command == 'd':
      logger.setLevel(logging.DEBUG)

    elif command == 'D':
      logger.setLevel(logging.INFO)

    elif command == 'a':
      logger.info(repr(self.ns.actions))

    elif command.startswith('x'):
      _, arg = command.split(' ', 1)
      try:
        self.update_actions(arg)
      except ValueError:
        logger.warn('usage: x actions:conditions')

    else: # show progress

      thread_progress = self.thread_progress
      num_threads = self.num_threads
      total_size = self.ns.total_size

      total_count = sum(p.done_count+p.skip_count for p in thread_progress)
      speed_avg = num_threads / (sum(sum(p.seconds) / len(p.seconds) for p in thread_progress) / num_threads)
      if total_size >= maxint:
        etc_time = 'inf'
        remain_time = 'inf'
      else:
        remain_seconds = (total_size - total_count) / speed_avg
        remain_time = pprint_seconds(remain_seconds, '%02d:%02d:%02d')
        etc_seconds = datetime.now() + timedelta(seconds=remain_seconds)
        etc_time = etc_seconds.strftime('%H:%M:%S')

      logger.info('Progress: {0:>3}% ({1}/{2}) | Speed: {3:.0f} r/s | ETC: {4} ({5} remaining) {6}'.format(
        total_count * 100/total_size,
        total_count,
        total_size,
        speed_avg,
        etc_time,
        remain_time,
        self.ns.paused and '| Paused' or ''))

      if command == 'f':
        for i, p in enumerate(thread_progress):
          total_count = p.done_count + p.skip_count
          logger.info(' {0:>3}: {1:>3}% ({2}/{3}) {4}'.format(
            '#%d' % (i+1),
            int(100*total_count/(1.0*total_size/num_threads)),
            total_count,
            total_size/num_threads,
            p.current))

# }}}

# Response_Base {{{
def match_range(size, val):
  if '-' in val:
    size_min, size_max = val.split('-')

    if not size_min and not size_max:
      raise ValueError('Invalid interval')

    elif not size_min: # size == -N
      return size <= float(size_max)

    elif not size_max: # size == N-
      return size >= float(size_min)

    else:
      size_min, size_max = float(size_min), float(size_max)
      if size_min >= size_max:
        raise ValueError('Invalid interval')

      return size_min <= size <= size_max

  else:
    return size == float(val)

class Response_Base:

  available_conditions = (
    ('code', 'match status code'),
    ('size', 'match size (N or N-M or N- or -N)'),
    ('time', 'match time (N or N-M or N- or -N)'),
    ('mesg', 'match message'),
    ('fgrep', 'search for string in mesg'),
    ('egrep', 'search for regex in mesg'),
    )

  indicatorsfmt = [('code', -5), ('size', -4), ('time', 7)]

  def __init__(self, code, mesg, timing=0, trace=None):
    self.code = code
    self.mesg = mesg
    self.time = timing.time if isinstance(timing, Timing) else timing
    self.size = len(mesg)
    self.trace = trace

  def indicators(self):
    return self.code, self.size, '%.3f' % self.time

  def __str__(self):
    return self.mesg

  def match(self, key, val):
    return getattr(self, 'match_'+key)(val)

  def match_code(self, val):
    return re.match('%s$' % val, str(self.code))

  def match_size(self, val):
    return match_range(self.size, val)

  def match_time(self, val):
    return match_range(self.time, val)

  def match_mesg(self, val):
    return val == self.mesg

  def match_fgrep(self, val):
    return val in str(self)

  def match_egrep(self, val):
    return re.search(val, str(self))

  def dump(self):
    return self.trace or str(self)

  def str_target(self):
    return ''

class Timing:
  def __enter__(self):
    self.t1 = time()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.time = time() - self.t1

# }}}

# TCP_Cache {{{
class TCP_Connection:
  def __init__(self, fp, banner=None):
    self.fp = fp
    self.banner = banner

  def close(self):
    self.fp.close()

class TCP_Cache:

  available_actions = (
    ('reset', 'close current connection in order to reconnect next time'),
    )

  available_options = (
    ('persistent', 'use persistent connections [1|0]'),
    )

  def __init__(self):
    self.cache = {} # {'10.0.0.1:22': ('root', conn1), '10.0.0.2:22': ('admin', conn2),
    self.curr = None

  def __del__(self):
    for _, (_, c) in self.cache.items():
      c.close()
    self.cache.clear()

  def bind(self, host, port, *args, **kwargs):

    hp = '%s:%s' % (host, port)
    key = ':'.join(map(str, args))

    if hp in self.cache:
      k, c = self.cache[hp]

      if key == k:
        self.curr = hp, k, c
        return c.fp, c.banner

      else:
        c.close()
        del self.cache[hp]

    self.curr = None

    logger.debug('connect')
    conn = self.connect(host, port, *args, **kwargs)

    self.cache[hp] = (key, conn)
    self.curr = hp, key, conn

    return conn.fp, conn.banner

  def reset(self, **kwargs):
    if self.curr:
      hp, _, c = self.curr

      c.close()
      del self.cache[hp]

      self.curr = None

# }}}
