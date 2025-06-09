#!/usr/bin/env python3

import sys
import datetime
import time


def epoch_to_human_readable(epoch_time):
    """
    Convert epoch time to human-readable format.
    
    Args:
        epoch_time (str or int): Epoch time in seconds or milliseconds
        
    Returns:
        str: Human-readable date and time
    """
    try:
        # Convert input to integer
        epoch_time = int(epoch_time)
        
        # Check if millisecond format (13 digits) or second format (10 digits)
        if len(str(epoch_time)) > 10:
            # Millisecond format - convert to seconds for datetime
            seconds = epoch_time / 1000
        else:
            # Standard epoch format (seconds)
            seconds = epoch_time
            
        # Convert to datetime and format
        dt = datetime.datetime.fromtimestamp(seconds)
        human_readable = dt.strftime('%m/%d/%Y %H:%M:%S')
        
        # Add timezone information
        timezone = time.strftime('%Z', time.localtime(seconds))
        return f"{human_readable} {timezone}"
        
    except ValueError as e:
        return f"Error: Invalid epoch time format - {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"


def main():
    """Main function to handle command-line arguments."""
    # Check if an epoch time was provided as a command-line argument
    if len(sys.argv) != 2:
        # Get current epoch time in both formats for examples
        current_epoch_seconds = int(time.time())
        current_epoch_milliseconds = int(time.time() * 1000)
        
        print("Usage: python epoch_converter.py [epoch_time]")
        print("Examples:")
        print(f"  python epoch_converter.py {current_epoch_seconds}      # Current epoch (seconds)")
        print(f"  python epoch_converter.py {current_epoch_milliseconds}   # Current epoch (milliseconds)")
        return
    
    epoch_time = sys.argv[1]
    result = epoch_to_human_readable(epoch_time)
    #print(f"Epoch: {epoch_time}")
    #print(f"Human-readable: {result}")
    print(result)
    

if __name__ == "__main__":
    main()
