import multiprocessing

class Logger:
  def __init__(self, queue):
    self.queue = queue
    self.name = multiprocessing.current_process().name

  def send(self, action, *args):
    self.queue.put((self.name, action, args))

  def quit(self):
    self.send('quit')

  def headers(self):
    self.send('headers')

  def result(self, *args):
    self.send('result', *args)

  def save(self, *args):
    self.send('save', *args)

  def setLevel(self, level):
    self.send('setLevel', level)

  def warn(self, msg):
    self.send('warn', msg)

  def info(self, msg):
    self.send('info', msg)

  def debug(self, msg):
    self.send('debug', msg)

