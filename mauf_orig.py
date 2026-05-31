from manuf import manuf

# Initialize the parser (it will load the Wireshark database format)
parser = manuf.MacParser()

# Perform a MAC address lookup
mac_address = "BC:EE:7B:00:00:00"
vendor_info = parser.get_manuf(mac_address)
full_name = parser.get_comment(mac_address)

print(f"Vendor Short: {vendor_info}") # Output: AsustekC
print(f"Full Company: {full_name}")   # Output: ASUSTek COMPUTER INC.