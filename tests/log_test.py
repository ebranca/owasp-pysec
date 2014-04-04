print "========"
print "LOG TEST"
print "========"

import pysec
from pysec import log

log.register_actions(
    'LOG_TEST',
    'LOG_MAIN'
)
log.register_errors(
    'IS_FALSE'
)

log.start_log(log.actions.LOG_TEST)
log.add_global_emit(log.print_emitter)


NUM = 0

with log.ctx(log.actions.LOG_MAIN):
    if NUM == 0:
        log.error(log.errors.IS_FALSE, num=NUM)
    try:
        pysec.load.importlib('test')
    except ImportError:
        print "library 'test' doesn't exist"
