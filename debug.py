import os
import py3dbg

from dotenv import load_dotenv

from Grabber.debug.debugger import Debugger
from Grabber.logs.logger import initLogging, log


def breakpoint():
    print("ok")
    return py3dbg.defines.DBG_CONTINUE


def main():
    load_dotenv()
    initLogging(0, os.environ["LOG_PATH"])

    while (1):
        name = input("Name: ")
        debugger = Debugger(os.environ["SAMPLE_PATH"] + "/" + name)

        debugger.addBreakpoint("kernel32", "VirtualProtect", breakpoint)
        debugger.run()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(30, str(e))
        exit(1)
