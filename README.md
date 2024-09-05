# Bulk Port Scanner
Designed to check customer's IPs via CSV to see if they have the top 100 ports open.

**Requires** NMap to be installed onto your device to call the scan function, currently this only scans top 100 ports, otherwise it'll be a very slow process script - https://nmap.org/

**Application Preview with success and error examples:**

![zJasTALDJv](https://github.com/user-attachments/assets/ae6a11f1-3e64-4337-86ae-2211bf3547b4)

**Example Export:**

![image](https://github.com/user-attachments/assets/0c382e60-b655-4133-84dc-e7e551ee4b96)

-----
**How to use:**

1. Ensure NMap is installed on the device
2. Download the latest release from Github - Unzip into a safe location on your computer
3. Ensure A/V does not block this application as it's not signed, or run the source code.
4. Run Application from \Bulk Port Scanner v1.0.2\dist\Bulk Port Scanner v1.0.2\Bulk Port Scanner.exe
5. Click the "Start Scan"
6. Select your Input CSV (Example CSV on here for you)
7. Select your save location and name
8. Wait
9. If you need to stop the scan, click stop. It will gracefully stop and still export the data.

You you get command prompts coming up and disappearing, this is normal, this is just the NMap wrapper running for each scan.

-----
This application isn't signed, just compiled to make it easier than running the script, if you need to run or edit the source, just install python-nmap and python on to your device.

By using this tool, you accept that you have full authority to scan the public IP from the owner of it.
-----

**Development Roadmap**

Completed v1.0.2 - Refreshed GUI Interface + Prompt for Save Locations

TBA - Custom Port Detection + Quick Select Top 100 Ports

TBA - Progress Bar on completion length

TBA - NMap Parallel Processing

TBA - Further Reporting, such as flagging ports of concern

TBA - Reviewing Results via GUI + Filtering
