import socket
import sys

# Leave the socket paths for the service's readiness check. The test manager
# then execs its stand-in binary so the service can verify the process image.
for index, argument in enumerate(sys.argv[:-1]):
    if argument in ("--control", "--control4", "--control6"):
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(sys.argv[index + 1])
