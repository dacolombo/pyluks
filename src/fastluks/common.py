# COMMON FUNCTIONS
# Common functions for both fast_luks_lib and luksctl_lib

# Import dependencies
import subprocess

#__________________________________
# Function to run bash commands
def run_command(cmd, LOGFILE=None):
    """
    Run subprocess call redirecting stdout, stderr and the command exit code.
    """
    proc = subprocess.Popen(args=cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    communicateRes = proc.communicate()
    stdout, stderr = [x.decode('utf-8') for x in communicateRes]
    status = proc.wait()

    # Functionality to replicate cmd >> "$LOGFILE" 2>&1
    if LOGFILE != None:
        with open(LOGFILE, 'a+') as log:
            log.write(f'{stdout}\n{stderr}')
    
    return stdout, stderr, status