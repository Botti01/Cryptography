"""
    
Read the code. If you really understood it, you can correctly guess the mode. 
If you do it with a probability higher than 2^128 you'll get the flag.

nc 130.192.5.212 6531
    
"""


from pwn import remote
import sys

host = "130.192.5.212"
port = 6531

conn = remote(host, port)

def recv_until_prompt(prompt):
    """Receives data until the specified prompt is found."""
    return conn.recvuntil(prompt.encode()).decode()

try:
    for i in range(128):
        # Wait until the "Challenge" prompt arrives
        challenge_line = recv_until_prompt("Challenge")
        print(f"Challenge {i}: {challenge_line.strip()}")
        # print(challenge_line.strip())
        
        # Wait for the prompt "The otp I'm using: " and read the complete line
        otp_line = recv_until_prompt("The otp I'm using: ")
        # At this point, conn.recvline() should contain the OTP in hexadecimal
        otp_rest = conn.recvline().decode().strip()
        otp_hex = otp_rest  # should be a hexadecimal string
        print("OTP:", otp_hex)
        
        # Wait for the prompt "Input: " (which might be printed inline with the output)
        recv_until_prompt("Input: ")
        # Send the OTP as input: this way the plaintext will be 32 bytes of 0.
        conn.sendline(otp_hex)
        
        # Now wait for "Output: " to get the ciphertext
        recv_until_prompt("Output: ")
        ciphertext_line = conn.recvline().decode().strip()
        # The ciphertext should be in the format: <ciphertext_hex>
        # If there are spaces or other characters, you can perform additional parsing.
        ciphertext_hex = ciphertext_line.split()[0]
        print("Ciphertext:", ciphertext_hex)
        
        # Split the ciphertext into two blocks of 16 bytes (32 hexadecimal characters)
        block1 = ciphertext_hex[:32]
        block2 = ciphertext_hex[32:64]
        
        if block1 == block2:
            mode_guess = "ECB"
        else:
            mode_guess = "CBC"
        print("Guessed mode:", mode_guess)
        
        # Wait for the prompt "What mode did I use? (ECB, CBC)" to send the response
        recv_until_prompt("What mode did I use? (ECB, CBC)")
        conn.sendline(mode_guess)
        
        # Read the server's response for this round
        feedback = conn.recvline().decode().strip()
        print("Feedback:", feedback)
        
        if "Wrong" in feedback:
            print("Round failed!")
            conn.close()
            sys.exit(1)
    
    # If all 128 rounds are guessed correctly, the flag will be printed
    # flag_line = conn.recvline().decode().strip()
    # print("Flag:", flag_line)
    remaining = conn.recvall(timeout=3).decode()
    print(remaining)
    
except Exception as e:
    print("Error:", e)
finally:
    conn.close()



# Flag: CRYPTO25{3709585c-5eda-4f6a-b1e5-a93e0cf99f93}