import logging
import time
from termcolor import colored
from components.ingestor import createfile_nocollision
from oberon_framework import log_banner


def configure_logging():
    current_date = time.strftime("%d-%m-%Y", time.localtime())
    log_file = createfile_nocollision(f"log_{current_date}", ".log")
        
    logging.basicConfig(filename=log_file, 
                        filemode="a", 
                        encoding='utf-8',
                        format="'%(asctime)s' - %(name)s → %(levelname)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S", level=logging.DEBUG)  
  
    with open(log_file, "w") as file_log:
        file_log.write(log_banner())

def log_activity(audit_message, log_level):
    try:
        logger = logging.getLogger()
        log_func = getattr(logger, log_level.lower())
        log_func(audit_message)
    except Exception as e:
        print(colored(f"[-] Unable to add log to 'th3executor_activity.log' due to {e}. Skipping audit", "red"))   
