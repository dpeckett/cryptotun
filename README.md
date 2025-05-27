> ⚠️ **WARNING**  
> This is a **very insecure prototype**.  
> Do **not** use in production or expose to untrusted networks.  
> It is intended for experimental or educational purposes only.

# Cryptotun – A Minimal Secure Tunneling Device

Cryptotun is a Linux kernel module that creates a virtual layer 3 point-to-point 
network interface capable of tunneling IP packets securely over UDP, with 
authentication and encryption provided by AES128-GCM-SHA256.

The module is designed to be as minimal and focused strictly on packet handling.
As much as possible is left to userspace, including key management and
authentication.