# Import dependencies
import subprocess
import logging

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


#__________________________________
# Create logging facility
def create_logger(logfile, name):

    # Define logging format
    formatter = logging.Formatter('%(levelname)s %(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    
    # Define logging handler
    handler = logging.FileHandler(logfile, mode='a+')  
    handler.setFormatter(formatter)

    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(0)
    logger.addHandler(handler)

    return logger
