# Bulk Port Scanner
Designed to check customer's IPs via CSV to see if they have the top 100 ports open.

**Requires ** NMap to be installed onto your device to call the scan function, currently this only scans top 100 ports, otherwise it'll be a very slow process script - https://nmap.org/

Example Export:
![image](https://github.com/user-attachments/assets/0c382e60-b655-4133-84dc-e7e551ee4b96)

-----
**How to use:**

1. Ensure NMap is installed on the device
2. Download "Initial" release from Github - Unzip into a safe location on your computer
3. Ensure A/V does not block this application as it's not signed, or run the source code.
4. You will be prompted with a File Explorer prompt to select your customer CSV list
5. Wait for the script to run
6. CSV will be exported to the dist folder of where you downloaded the application.

-----
This application isn't signed, just compiled to make it easier than running the script, if you need to run or edit the source, just install python-nmap and python on to your device.
-----
By using this tool, you accept that you have full authority to scan the public IP from the owner of it.
