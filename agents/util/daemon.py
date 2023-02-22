import os, sys, atexit
from signal import SIGTERM, signal
import time

class Daemon(object):
    '''
    A generic daemon class.

    Usage: subclass the Daemon class and override the run() method
    '''
    def __init__(self, pidfile, processname='', stdin='/dev/null',
                 stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.processname = processname

    def daemonize(self):
        '''
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        '''
        try:
            pid = os.fork()
            if pid > 0:
                # kill first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write('fork #1 failed: %d (%s)\n' % (e.errno, str(e)))
            sys.exit(1)

        os.chdir('/')
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write('fork #2 failed: %d (%s)\n' % (e.errno, str(e)))
            sys.exit(1)

        # redirect standard file descriptor
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, 'r')
        so = open(self.stdout, 'a+')
        se = open(self.stderr, 'a+')

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        signal(SIGTERM, self.cleanup)
        pid = str(os.getpid())
        open(self.pidfile, 'w+').write('%s\n' % pid)

    def delpid(self):
        if hasattr(self, 'before_stop'):
            self.before_stop()

    def cleanup(self, _signo, _stack_frame):
        sys.exit(0)

    def start(self):
        '''
        Start the daemon
        '''

        # Check for a pidfile to see if the daemon already runs
        try:
            pf = open(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            message = 'pidfile %s is already exist. '\
                'Check that %s runs as pid %d\n' \
                % (self.pidfile, self.processname, pid)
            sys.stderr.write(message)
            sys.exit(1)

        # Start the daemon
        sys.stdout.write('Daemonizing %s.\n' % self.processname)
        self.daemonize()
        self.run()

    def stop(self):
        '''
        Stop the daemon
        '''

        # Get the pid from the pidfile
        try:
            pf = open(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            message = 'pidfile %s does not exist. %s may not running\n' \
                % (self.pidfile, self.processname)
            sys.stderr.write(message)
            return False

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError as e:
            # TODO check that it is OK to check with string
            if(str(e).find('No such process')) > 0:
                sys.stdout.write('%s is stopped successfully\n' % self.processname)
                os.remove(self.pidfile)
            else:
                sys.stderr.write(str(e))
                sys.exit(1)
        return True

    def restart(self):
        '''
        Restart the daemon
        '''
        self.stop()
        self.start()

    def status(self):
        # Get the pid from the pidfile
        try:
            pf = open(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            sys.stdout.write('%s is not running\n' % self.processname)
        else:
            sys.stdout.write('%s is running as pid: %d\n' %(self.processname, pid))

    def run(self):
        '''
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart(). asdfasdfsadf
        '''
