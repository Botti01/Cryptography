"""
    
Read the code. If you really understood it, you can correctly guess the mode. 
If you do it with a probability higher than 2^128 you'll get the flag.

nc 130.192.5.212 6531
    
"""


from pwn import remote      # Import the pwntools library for remote connections
import sys                  # Import the sys module for system-level operations

# Define the host and port of the remote server
host = "130.192.5.212"
port = 6531

# Establish a remote connection to the server
conn = remote(host, port)

def recv_until_prompt(prompt):
    """
    Receives data from the server until the specified prompt is found.
    Args:
        prompt (str): The string to wait for in the server's response.
    Returns:
        str: The data received from the server up to and including the prompt.
    """
    return conn.recvuntil(prompt.encode()).decode()

try:
    # Loop through 128 rounds of the challenge
    for i in range(128):
        # Wait until the "Challenge" prompt arrives and print it
        challenge_line = recv_until_prompt("Challenge")
        print(f"Challenge {i}: {challenge_line.strip()}")  # Log the challenge number and details
        
        # Wait for the prompt "The otp I'm using: " and read the OTP (One-Time Pad) in hexadecimal
        otp_line = recv_until_prompt("The otp I'm using: ")
        print(otp_line)  # Log the OTP prompt for debugging
        
        # Read the OTP value from the server
        otp_rest = conn.recvline().decode().strip()  # The OTP is expected to be a hexadecimal string
        otp_hex = otp_rest  # Assign the OTP value to a variable
        print("OTP:", otp_hex)  # Log the OTP for debugging
        
        # Wait for the prompt "Input: " to send the plaintext
        recv_until_prompt("Input: ")
        # Send the OTP as input. This ensures the plaintext is 32 bytes of 0.
        conn.sendline(otp_hex)
        
        # Wait for the server to respond with the ciphertext
        recv_until_prompt("Output: ")
        ciphertext_line = conn.recvline().decode().strip()  # Read the ciphertext line
        # The ciphertext is expected to be in hexadecimal format
        ciphertext_hex = ciphertext_line.split()[0]  # Extract the ciphertext (first part of the line)
        print("Ciphertext:", ciphertext_hex)  # Log the ciphertext for debugging
        
        # Split the ciphertext into two blocks of 16 bytes each (32 hexadecimal characters per block)
        block1 = ciphertext_hex[:32]  # First 16 bytes (32 hex characters)
        block2 = ciphertext_hex[32:64]  # Second 16 bytes (32 hex characters)
        
        # Determine the encryption mode based on the ciphertext blocks
        if block1 == block2:
            # If the two blocks are identical, the mode is likely ECB (Electronic Codebook)
            mode_guess = "ECB"
        else:
            # If the blocks differ, the mode is likely CBC (Cipher Block Chaining)
            mode_guess = "CBC"
        print("Guessed mode:", mode_guess)  # Log the guessed mode
        
        # Wait for the prompt "What mode did I use? (ECB, CBC)" to send the guessed mode
        recv_until_prompt("What mode did I use? (ECB, CBC)")
        conn.sendline(mode_guess)  # Send the guessed mode to the server
        
        # Read the server's feedback for this round
        feedback = conn.recvline().decode().strip()
        print("Feedback:", feedback)  # Log the feedback
        
        # If the feedback indicates a wrong guess, terminate the script
        if "Wrong" in feedback:
            print("Round failed!")  # Log the failure
            conn.close()  # Close the connection
            sys.exit(1)  # Exit the script with an error code
    
    # If all 128 rounds are guessed correctly, the server will send the flag
    remaining = conn.recvall(timeout=3).decode()  # Read any remaining data from the server
    print(remaining)  # Log the flag or any additional output
    
except Exception as e:
    # Handle any exceptions that occur during execution
    print("Error:", e)  # Log the error message
finally:
    # Ensure the connection is closed at the end
    conn.close()



# Flag: CRYPTO25{3709585c-5eda-4f6a-b1e5-a93e0cf99f93}