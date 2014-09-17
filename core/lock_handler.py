import os
import sys

class LockHandlerException(Exception):
    def __init__(self, error):
        self.error = error

    def __str__(self):
        return repr(self.error)

class LockHandler():
    def __init__(self, working_dir, logger, override_lock_handler, debug):
        self.lock_file = "%srepoguard.pid" % working_dir
        self.aborted_state_file = "%saborted_state.lock" % working_dir
        self.logger = logger
        self.override_lock_handler = override_lock_handler
        self.debug = debug

    def put_lock(self):
        with open(self.lock_file, "w") as lockfile:
            lockfile.write(str(os.getpid()))

    def release_lock(self):
        if not self.override_lock_handler:
            os.remove(self.lock_file)

    def is_locked(self):
        if os.path.isfile(self.lock_file):
            with open(self.lock_file, "r") as lockfile:
                pid = lockfile.readline().strip()

            if os.path.exists("/proc/%s" % pid):
                return True
            else:
                self.logger.error('Lock there but script not running, removing lock entering aborted state...')
                self.release_lock()
                self.set_aborted()
                raise LockHandlerException("Found lock with PID %s, but process not found... ")
        else:
            self.logger.debug("pid file not found, not locked...")
            return False

    def set_aborted(self):
        with open(self.aborted_state_file, "w") as aborted_state_file:
            aborted_state_file.write('1')

    def is_aborted(self):
        return os.path.isfile(self.aborted_state_file)

    def start(self):
        if not self.override_lock_handler:
            if self.is_aborted() and self.debug:
                self.logger.info('Aborted state, quiting!')
                sys.exit()
            if self.is_locked():
                self.logger.info('Locked, script running... waiting.')
                sys.exit()
            self.put_lock()
