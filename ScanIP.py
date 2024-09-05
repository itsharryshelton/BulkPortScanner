import csv
import nmap
import time
import tkinter as tk
from tkinter import filedialog

#Read the input CSV function
def read_customers_from_csv(file_path):
    customer_list = []
    with open(file_path, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            customer_list.append({'customer_name': row['customer_name'], 'ip': row['ip']})
    return customer_list

#Scanning Function
def scan_ip(ip, nm):
    try:
        nm.scan(ip, arguments='--top-ports 100')
        return nm[ip]
    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        return None

#Export to CSV with details
def export_results_to_csv(scan_results, output_file):
    with open(output_file, mode='w', newline='') as file:
        fieldnames = ['customer_name', 'ip', 'port', 'state', 'name', 'product', 'version']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        
        for customer_name, ip, port_data in scan_results:
            for port in port_data:
                writer.writerow({
                    'customer_name': customer_name,
                    'ip': ip,
                    'port': port['port'],
                    'state': port['state'],
                    'name': port.get('name', ''),
                    'product': port.get('product', ''),
                    'version': port.get('version', '')
                })

#Select CSV GUI Prompt
def get_csv_file_path():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select the input CSV file",
        filetypes=[("CSV files", "*.csv")],
        defaultextension=".csv"
    )
    return file_path

#Main scan customer IPs function
def main():
    nm = nmap.PortScanner()
    input_file = get_csv_file_path()
    if not input_file:
        print("No file selected. Exiting.")
        return
    customer_list = read_customers_from_csv(input_file)
    
    scan_results = []

    for customer in customer_list:
        customer_name = customer['customer_name']
        ip = customer['ip']
        print(f"Scanning IP: {ip} for customer: {customer_name}")
        
        scan_data = scan_ip(ip, nm)
        if scan_data:
            port_data = []
            for proto in scan_data.all_protocols():
                ports = scan_data[proto].keys()
                for port in ports:
                    port_data.append({
                        'port': port,
                        'state': scan_data[proto][port]['state'],
                        'name': scan_data[proto][port].get('name', ''),
                        'product': scan_data[proto][port].get('product', ''),
                        'version': scan_data[proto][port].get('version', '')
                    })
            scan_results.append((customer_name, ip, port_data))
        time.sleep(1)  #\dmall delay between scans to avoid overloading the system

    #Export the results to an output CSV
    output_file = 'scan_results.csv'
    export_results_to_csv(scan_results, output_file)
    print(f"Scan results saved to {output_file}")

if __name__ == "__main__":
    main()
