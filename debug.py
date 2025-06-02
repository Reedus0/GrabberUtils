import os
import sys
import py3dbg

from dotenv import load_dotenv

from Grabber.debug.debugger import Debugger
from Grabber.logs.logger import initLogging, log


def breakpoint(_: py3dbg.pydbg):
    print("ok")
    return py3dbg.defines.DBG_CONTINUE


def main():
    if (len(sys.argv) < 2):
        print(f"Usage: {sys.argv[0]} sample")
        exit(1)

    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    name = sys.argv[1]
    debugger = Debugger(os.environ["SAMPLE_PATH"] + "/" + name)

    debugger.addBreakpoint("kernel32", "GetCurrentProcess", breakpoint)
    debugger.run()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(30, str(e))
        exit(1)
